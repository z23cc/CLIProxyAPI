package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	log "github.com/sirupsen/logrus"
)

// metaADWrSave is one recorded Store.Save call.
type metaADWrSave struct {
	id   string
	meta map[string]any
}

// metaADWrStore is a Store double: it records every Save, can be told to fail the next
// N saves, and can block saves that carry the auto-disable markers.
type metaADWrStore struct {
	mu       sync.Mutex
	saves    []metaADWrSave
	failures int
	// When blockOn is set, a Save carrying disabled=true sends on entered and waits on release.
	blockOn bool
	entered chan struct{}
	release chan struct{}
	// localThenFail models a store that writes the watched local file first and uploads
	// afterwards: a Save carrying the disable markers lands in localFiles and then fails.
	localThenFail bool
	localFiles    map[string]map[string]any
}

func (s *metaADWrStore) List(context.Context) ([]*Auth, error) { return nil, nil }
func (s *metaADWrStore) Delete(context.Context, string) error  { return nil }

func (s *metaADWrStore) Save(_ context.Context, a *Auth) (string, error) {
	meta := make(map[string]any, len(a.Metadata))
	for k, v := range a.Metadata {
		meta[k] = v
	}
	s.mu.Lock()
	s.saves = append(s.saves, metaADWrSave{id: a.ID, meta: meta})
	fail := s.failures > 0
	if fail {
		s.failures--
	}
	if s.localThenFail && meta["disabled"] == true {
		if s.localFiles == nil {
			s.localFiles = map[string]map[string]any{}
		}
		s.localFiles[a.ID] = meta
		fail = true
	}
	block := s.blockOn && meta["disabled"] == true
	entered, release := s.entered, s.release
	s.mu.Unlock()
	if block {
		entered <- struct{}{}
		<-release
	}
	if fail {
		return "", errors.New("store unavailable")
	}
	return a.ID, nil
}

func (s *metaADWrStore) failNext(n int) {
	s.mu.Lock()
	s.failures = n
	s.mu.Unlock()
}

func (s *metaADWrStore) armBlock() {
	s.mu.Lock()
	s.blockOn = true
	s.entered = make(chan struct{}, 4)
	s.release = make(chan struct{})
	s.mu.Unlock()
}

// markerSaves returns the metadata of every save that carries the auto-disable markers.
func (s *metaADWrStore) markerSaves() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, save := range s.saves {
		if save.meta["disabled"] == true && save.meta[metaADKeyDisabledBy] == metaADDisabledBy {
			out = append(out, save.meta)
		}
	}
	return out
}

func metaADWrConfig(enabled bool, maxPerHour int) *internalconfig.Config {
	return &internalconfig.Config{Routing: internalconfig.RoutingConfig{MetaAutoDisable: internalconfig.MetaAutoDisableConfig{Enabled: enabled, MaxPerHour: maxPerHour}}}
}

// newMetaADWrManager builds a manager on the store double. registerModels registers the
// three test models in the global registry for every auth.
func newMetaADWrManager(t *testing.T, cfg *internalconfig.Config, store Store, exec ProviderExecutor, registerModels bool, auths ...*Auth) *Manager {
	t.Helper()
	m := NewManager(store, nil, nil)
	m.RegisterExecutor(exec)
	m.SetConfig(cfg)
	reg := registry.GetGlobalRegistry()
	models := []*registry.ModelInfo{{ID: metaADModelA}, {ID: metaADModelB}, {ID: metaADModelC}}
	for _, a := range auths {
		id := a.ID
		if registerModels {
			reg.RegisterClient(id, "meta", models)
			t.Cleanup(func() { reg.UnregisterClient(id) })
		}
		if _, err := m.Register(context.Background(), a); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}
	return m
}

// metaADWrFileAuth is a file-style Meta credential with unrelated metadata that must survive.
func metaADWrFileAuth(id, key, dca string) *Auth {
	a := &Auth{
		ID:       id,
		Provider: "meta",
		Metadata: map[string]any{
			"type":         "meta",
			"access_token": key,
			"api_key":      key,
			"email":        id + "@example.invalid",
			"proxy_url":    "http://127.0.0.1:1",
			"priority":     5,
		},
	}
	if dca != "" {
		a.Metadata["dca_token"] = dca
	}
	return a
}

// metaADWrCraftConfirmed puts the live auth into a tracked+confirmed state directly.
func metaADWrCraftConfirmed(t *testing.T, m *Manager, id, reason string) {
	t.Helper()
	now := time.Now()
	m.mu.Lock()
	live := m.auths[id]
	metaADEnterPending(live, reason, now)
	metaADMarkConfirmed(live, now)
	if m.scheduler != nil {
		m.scheduler.upsertAuth(live.Clone())
	}
	m.mu.Unlock()
}

// metaADWrEpisode returns the episode the credential is in right now (zero when untracked).
func metaADWrEpisode(t *testing.T, m *Manager, id string) metaADEpisode {
	t.Helper()
	live, ok := m.GetByID(id)
	if !ok {
		return metaADEpisode{}
	}
	return live.metaAD.episode()
}

func metaADWrLimiterStamps(m *Manager) int {
	m.metaADLimiter.mu.Lock()
	defer m.metaADLimiter.mu.Unlock()
	return len(m.metaADLimiter.stamps)
}

// metaADWrRequireDisabled asserts the end state of a written disable.
func metaADWrRequireDisabled(t *testing.T, a *Auth, reason string) {
	t.Helper()
	if !a.Disabled || a.Status != StatusDisabled {
		t.Fatalf("Disabled=%v Status=%v, want disabled", a.Disabled, a.Status)
	}
	if want := fmt.Sprintf("disabled (meta %s)", reason); a.StatusMessage != want {
		t.Fatalf("StatusMessage = %q, want %q", a.StatusMessage, want)
	}
	if _, _, _, ok := a.MetaAutoDisableStatus(); ok {
		t.Fatalf("MetaAutoDisableStatus is ok for a disabled credential")
	}
	if a.metaAD.state != "" {
		t.Fatalf("raw metaAD = %+v, want cleared", a.metaAD)
	}
	if !a.NextRefreshAfter.IsZero() || !a.NextRetryAfter.IsZero() || a.LastError != nil || a.Unavailable {
		t.Fatalf("nextRefresh=%v nextRetry=%v lastErr=%v unavailable=%v, want all cleared", a.NextRefreshAfter, a.NextRetryAfter, a.LastError, a.Unavailable)
	}
	if metaADEligible(a) {
		t.Fatalf("a disabled credential must not be eligible")
	}
	if a.Metadata["disabled"] != true || a.Metadata[metaADKeyDisabledBy] != metaADDisabledBy || a.Metadata[metaADKeyReason] != reason {
		t.Fatalf("metadata markers = %v, want disabled/cliproxyapi/%s", a.Metadata, reason)
	}
	metaADWrRequireTimestamp(t, a.Metadata[metaADKeyDisabledAt])
	for _, model := range []string{metaADModelA, metaADModelB, metaADModelC, ""} {
		if blocked, _, _ := isAuthBlockedForModel(a, model, time.Now()); !blocked {
			t.Fatalf("disabled credential not blocked for model %q", model)
		}
	}
	if m := a.Metadata["priority"]; m != 5 || a.Metadata["proxy_url"] != "http://127.0.0.1:1" {
		t.Fatalf("unrelated metadata lost: %v", a.Metadata)
	}
}

func metaADWrRequireTimestamp(t *testing.T, raw any) {
	t.Helper()
	text, _ := raw.(string)
	at, err := time.Parse(time.RFC3339, text)
	if err != nil || !strings.HasSuffix(text, "Z") {
		t.Fatalf("disabled_at = %v, want RFC3339 UTC", raw)
	}
	if d := time.Since(at); d > 10*time.Second || d < -10*time.Second {
		t.Fatalf("disabled_at = %v, not within 10s of now", at)
	}
}

// metaADWrRequireSingleWrite asserts exactly one save carried the markers and that the
// unrelated metadata survived in it.
func metaADWrRequireSingleWrite(t *testing.T, store *metaADWrStore, reason string) {
	t.Helper()
	saves := store.markerSaves()
	if len(saves) != 1 {
		t.Fatalf("saves with disable markers = %d, want exactly 1", len(saves))
	}
	meta := saves[0]
	if meta[metaADKeyReason] != reason {
		t.Fatalf("saved disabled_reason = %v, want %s", meta[metaADKeyReason], reason)
	}
	metaADWrRequireTimestamp(t, meta[metaADKeyDisabledAt])
	if meta["priority"] != 5 || meta["proxy_url"] != "http://127.0.0.1:1" || meta["email"] != metaADPrimaryID+"@example.invalid" {
		t.Fatalf("unrelated metadata lost in the saved file: %v", meta)
	}
}

func metaADWrWaitForGateWaiter(m *Manager, id string, want int) {
	state := m.metadataPersistPreempt(id)
	for {
		state.mu.Lock()
		waiters := state.waiters
		state.mu.Unlock()
		if waiters >= want {
			return
		}
		runtime.Gosched()
	}
}

func TestMetaAutoDisableWrite_DisableIsWrittenAfterConfirmation(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		setup  func(exec *metaADTestExecutor) *Auth
		enter  func(t *testing.T, m *Manager)
	}{
		{"mint_rejected", metaADReasonMintRejected,
			func(exec *metaADTestExecutor) *Auth {
				exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)}, metaADRefreshResult{err: metaADMintErr(http.StatusForbidden)})
				return metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary")
			}, nil},
		{"new_key_rejected", metaADReasonNewKeyRejected,
			func(exec *metaADTestExecutor) *Auth {
				exec.enqueue(metaADRefreshResult{mintInvalid: true})
				return metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary")
			}, nil},
		{"no_dca_token", metaADReasonNoDCAToken,
			func(*metaADTestExecutor) *Auth { return metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "") }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &metaADWrStore{}
			exec := newMetaADTestExecutor("dead-key-0")
			primary := tc.setup(exec)
			m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, exec, true, primary, metaADBackup())

			if _, err := metaADExecute(m, metaADModelA); err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if got := store.markerSaves(); len(got) != 0 {
				t.Fatalf("a disable was written before any confirmation: %v", got)
			}
			metaADRequireTracked(t, metaADGet(t, m, metaADPrimaryID), metaADStatePending, tc.reason)

			refreshesBefore := exec.RefreshCalls()
			metaADConfirmDue(m, metaADPrimaryID)

			metaADWrRequireDisabled(t, metaADGet(t, m, metaADPrimaryID), tc.reason)
			metaADWrRequireSingleWrite(t, store, tc.reason)
			wantMints := 0
			if tc.reason == metaADReasonMintRejected {
				wantMints = 1
			}
			if got := exec.RefreshCalls() - refreshesBefore; got != wantMints {
				t.Fatalf("confirmation Refresh calls = %d, want %d", got, wantMints)
			}

			// The credential is never selected again.
			primaryCalls := exec.CallsFor(metaADPrimaryID)
			for i := 0; i < 3; i++ {
				resp, err := metaADExecute(m, metaADModelA)
				if err != nil || string(resp.Payload) != metaADBackupID+":good-key" {
					t.Fatalf("Execute = (%q, %v), want the backup", resp.Payload, err)
				}
			}
			if got := exec.CallsFor(metaADPrimaryID); got != primaryCalls {
				t.Fatalf("the disabled primary received %d more upstream calls", got-primaryCalls)
			}
		})
	}
}

func TestMetaAutoDisableWrite_AlreadyDisabledIsNotOverwritten(t *testing.T) {
	cases := map[string]map[string]any{
		"admin_disabled": {},
		"usage_statistics_marker": {
			"disabled_by":     "usage-statistics",
			"disabled_reason": "x",
			"disabled_at":     "2020-01-02T03:04:05Z",
		},
	}
	for name, foreign := range cases {
		t.Run(name, func(t *testing.T) {
			store := &metaADWrStore{}
			exec := newMetaADTestExecutor("dead-key-0")
			exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
			m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, exec, true,
				metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary"), metaADBackup())
			if _, err := metaADExecute(m, metaADModelA); err != nil {
				t.Fatalf("Execute: %v", err)
			}
			metaADRequireTracked(t, metaADGet(t, m, metaADPrimaryID), metaADStatePending, metaADReasonMintRejected)

			// Someone else disables the credential while it is pending.
			if _, ok, err := m.Modify(context.Background(), metaADPrimaryID, 0, func(a *Auth) error {
				a.Disabled = true
				a.Status = StatusDisabled
				a.StatusMessage = "disabled by someone else"
				a.Metadata["disabled"] = true
				for k, v := range foreign {
					a.Metadata[k] = v
				}
				return nil
			}); err != nil || !ok {
				t.Fatalf("Modify = (%v, %v)", ok, err)
			}
			savesBefore := len(store.markerSaves())

			m.metaAutoDisableWrite(metaADPrimaryID, metaADWrEpisode(t, m, metaADPrimaryID))
			metaADMakeDue(m, metaADPrimaryID)
			m.metaAutoDisableSettle(metaADPrimaryID, metaADWrEpisode(t, m, metaADPrimaryID))

			got := metaADGet(t, m, metaADPrimaryID)
			if !got.Disabled || got.StatusMessage != "disabled by someone else" {
				t.Fatalf("disabled=%v message=%q, the foreign disable must stay as it was", got.Disabled, got.StatusMessage)
			}
			if got.metaAD.state != "" {
				t.Fatalf("raw metaAD = %+v, want tracking cleared", got.metaAD)
			}
			for k, want := range foreign {
				if got.Metadata[k] != want {
					t.Fatalf("foreign marker %s = %v, want %v (overwritten)", k, got.Metadata[k], want)
				}
			}
			if _, has := foreign["disabled_by"]; !has {
				if _, written := got.Metadata[metaADKeyDisabledBy]; written {
					t.Fatalf("auto-disable markers were written over an admin disable: %v", got.Metadata)
				}
			}
			if after := len(store.markerSaves()); after != savesBefore {
				t.Fatalf("auto-disable saves changed %d -> %d", savesBefore, after)
			}
			if stamps := metaADWrLimiterStamps(m); stamps != 0 {
				t.Fatalf("limiter stamps = %d, want 0", stamps)
			}
		})
	}
}

func TestMetaAutoDisableWrite_CredentialChangedDuringWriteIsNotDisabled(t *testing.T) {
	store := &metaADWrStore{}
	exec := newMetaADTestExecutor()
	m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, exec, false,
		metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary"))
	metaADWrCraftConfirmed(t, m, metaADPrimaryID, metaADReasonMintRejected)

	release := m.lockAuthMutation(metaADPrimaryID)
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.metaAutoDisableWrite(metaADPrimaryID, metaADWrEpisode(t, m, metaADPrimaryID))
	}()
	// The write decided to write and is now blocked in Modify's gate acquisition.
	metaADWrWaitForGateWaiter(m, metaADPrimaryID, 1)

	replacement := metaADWrFileAuth(metaADPrimaryID, "login-key-9", "dca:login")
	committed, ok, persistCooldown, err := m.updateInternalLocked(context.Background(), nil, replacement, updateModeReplace)
	if err != nil || !ok {
		t.Fatalf("updateInternalLocked = (%v, %v, %v)", ok, committed != nil, err)
	}
	release()
	m.finishAuthUpdate(context.Background(), committed, persistCooldown)
	<-done

	got := metaADGet(t, m, metaADPrimaryID)
	if got.Disabled || got.Status == StatusDisabled {
		t.Fatalf("the replacement credential was disabled")
	}
	for _, key := range []string{"disabled", metaADKeyDisabledBy, metaADKeyReason, metaADKeyDisabledAt} {
		if v, has := got.Metadata[key]; has && v != false {
			t.Fatalf("replacement carries marker %s=%v", key, v)
		}
	}
	if saves := store.markerSaves(); len(saves) != 0 {
		t.Fatalf("a disable was saved for the replaced credential: %v", saves)
	}
	if stamps := metaADWrLimiterStamps(m); stamps != 0 {
		t.Fatalf("limiter stamps = %d, want 0 (slot given back)", stamps)
	}
}

func TestMetaAutoDisableWrite_RegistrationChangedIsNotDisabled(t *testing.T) {
	store := &metaADWrStore{}
	exec := newMetaADTestExecutor()
	m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, exec, false,
		metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary"))
	metaADWrCraftConfirmed(t, m, metaADPrimaryID, metaADReasonMintRejected)
	epochBefore := metaADGet(t, m, metaADPrimaryID).RegistrationEpoch

	m.Remove(context.Background(), metaADPrimaryID)
	if _, err := m.Register(context.Background(), metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if metaADGet(t, m, metaADPrimaryID).RegistrationEpoch == epochBefore {
		t.Fatalf("precondition: registration epoch did not change")
	}

	m.metaAutoDisableWrite(metaADPrimaryID, metaADWrEpisode(t, m, metaADPrimaryID))

	got := metaADGet(t, m, metaADPrimaryID)
	if got.Disabled || len(store.markerSaves()) != 0 || metaADWrLimiterStamps(m) != 0 {
		t.Fatalf("disabled=%v marker saves=%d stamps=%d, want nothing written", got.Disabled, len(store.markerSaves()), metaADWrLimiterStamps(m))
	}
}

func TestMetaAutoDisableWrite_StaleRecordedEpochWritesNothing(t *testing.T) {
	store := &metaADWrStore{}
	exec := newMetaADTestExecutor()
	m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, exec, false,
		metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary"))
	metaADWrCraftConfirmed(t, m, metaADPrimaryID, metaADReasonMintRejected)
	// The recorded episode epoch is older than the live registration epoch.
	m.mu.Lock()
	live := m.auths[metaADPrimaryID]
	live.RegistrationEpoch = live.metaAD.epoch + 3
	m.mu.Unlock()

	m.metaAutoDisableWrite(metaADPrimaryID, metaADWrEpisode(t, m, metaADPrimaryID))

	got := metaADGet(t, m, metaADPrimaryID)
	if got.Disabled || len(store.markerSaves()) != 0 {
		t.Fatalf("disabled=%v marker saves=%d, want nothing written", got.Disabled, len(store.markerSaves()))
	}
	metaADRequireTracked(t, got, metaADStatePending, metaADReasonMintRejected)
	if !got.metaAD.confirmed {
		t.Fatalf("metaAD.confirmed = false, want the credential to stay confirmed")
	}
	if stamps := metaADWrLimiterStamps(m); stamps != 0 {
		t.Fatalf("limiter stamps = %d, want the slot given back", stamps)
	}
	if got.NextRefreshAfter.IsZero() || !got.Unavailable {
		t.Fatalf("nextRefresh=%v unavailable=%v, want blocked with a retry time", got.NextRefreshAfter, got.Unavailable)
	}
}

func TestMetaAutoDisableWrite_ApplyDisableGuards(t *testing.T) {
	newConfirmed := func() (*Manager, *Auth, metaAutoDisableState) {
		m := NewManager(nil, nil, nil)
		m.SetConfig(metaADWrConfig(true, 0))
		a := metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary")
		a.RegistrationEpoch = 5
		now := time.Now()
		metaADEnterPending(a, metaADReasonMintRejected, now)
		metaADMarkConfirmed(a, now)
		return m, a, a.metaAD
	}

	t.Run("applies when every guard holds", func(t *testing.T) {
		m, a, state := newConfirmed()
		if err := m.metaADApplyDisable(a, state, time.Now()); err != nil {
			t.Fatalf("metaADApplyDisable = %v, want nil", err)
		}
		metaADWrRequireDisabled(t, a, metaADReasonMintRejected)
	})

	guards := map[string]func(m *Manager, a *Auth){
		"fingerprint mismatch": func(_ *Manager, a *Auth) { a.Metadata["api_key"] = "other-key" },
		"not confirmed":        func(_ *Manager, a *Auth) { a.metaAD.confirmed = false },
		"other episode":        func(_ *Manager, a *Auth) { a.metaAD.since = a.metaAD.since.Add(time.Second) },
		"already disabled":     func(_ *Manager, a *Auth) { a.Disabled = true },
		"config key": func(_ *Manager, a *Auth) {
			a.Attributes = map[string]string{"api_key": "dead-key-0", AttributeSource: "config:meta[abc]"}
		},
		"switch off": func(m *Manager, _ *Auth) { m.SetConfig(metaADWrConfig(false, 0)) },
	}
	for name, mutate := range guards {
		t.Run(name, func(t *testing.T) {
			m, a, state := newConfirmed()
			mutate(m, a)
			before := a.Clone()
			if err := m.metaADApplyDisable(a, state, time.Now()); !errors.Is(err, errMetaADWriteSkipped) {
				t.Fatalf("metaADApplyDisable = %v, want errMetaADWriteSkipped", err)
			}
			if !reflect.DeepEqual(a.Metadata, before.Metadata) || a.Disabled != before.Disabled || a.Status != before.Status ||
				a.StatusMessage != before.StatusMessage || a.metaAD != before.metaAD {
				t.Fatalf("a skipped apply mutated the auth: before=%+v after=%+v", before, a)
			}
		})
	}
}

func TestMetaAutoDisableWrite_WriteFailureKeepsCredentialBlockedAndRetriesLater(t *testing.T) {
	store := &metaADWrStore{}
	exec := newMetaADTestExecutor("dead-key-0")
	exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)}, metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
	m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, exec, true,
		metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary"), metaADBackup())
	if _, err := metaADExecute(m, metaADModelA); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	requireRetryLater := func(label string, before, after time.Time, wantStamps int) {
		t.Helper()
		got := metaADGet(t, m, metaADPrimaryID)
		if got.Disabled {
			t.Fatalf("%s: the disable was published although the save failed", label)
		}
		metaADRequireTracked(t, got, metaADStatePending, metaADReasonMintRejected)
		if !got.metaAD.confirmed {
			t.Fatalf("%s: metaAD.confirmed = false, want true", label)
		}
		metaADRequireDueIn(t, got, before, after, metaADWriteRetryDelay)
		if hasUnauthorizedAuthFailure(got) {
			t.Fatalf("%s: hasUnauthorizedAuthFailure = true", label)
		}
		metaADRequireBlockedEverywhere(t, got)
		// A failed save keeps its cap slot: the local file may already carry the disable.
		if stamps := metaADWrLimiterStamps(m); stamps != wantStamps {
			t.Fatalf("%s: limiter stamps = %d, want %d (a failed save keeps its slot)", label, stamps, wantStamps)
		}
	}

	// Confirmation: the mint is rejected again, but the save fails.
	store.failNext(2)
	before := time.Now()
	metaADConfirmDue(m, metaADPrimaryID)
	requireRetryLater("confirmation", before, time.Now(), 1)
	if got := exec.RefreshCalls(); got != 2 {
		t.Fatalf("Refresh calls = %d, want 2 (request mint + confirmation mint)", got)
	}

	// Real loop entry, second failing save: still a real retry time, never zero.
	runLoop := func() (nextAfterRefresh, nextAfterFinish time.Time) {
		ctx := context.Background()
		metaADMakeDue(m, metaADPrimaryID)
		l := newAuthAutoRefreshLoop(m, time.Second, 1)
		l.handleDueAuth(ctx, time.Now(), metaADPrimaryID)
		var job *authRefreshJob
		select {
		case job = <-l.jobs:
		default:
			t.Fatalf("no refresh job enqueued for the pending write")
		}
		if m.beginRefreshJob(ctx, job) {
			_, _ = m.refreshAuthForRequestAtEpoch(ctx, job.id, "", job.registrationEpoch)
		}
		nextAfterRefresh = metaADGet(t, m, metaADPrimaryID).NextRefreshAfter
		m.finishRefreshJob(job, time.Time{}, false)
		nextAfterFinish = metaADGet(t, m, metaADPrimaryID).NextRefreshAfter
		return nextAfterRefresh, nextAfterFinish
	}
	before = time.Now()
	afterRefresh, afterFinish := runLoop()
	after := time.Now()
	for label, next := range map[string]time.Time{"after refresh": afterRefresh, "after finishRefreshJob": afterFinish} {
		if next.Before(before.Add(metaADWriteRetryDelay-time.Second)) || next.After(after.Add(metaADWriteRetryDelay+time.Second)) {
			t.Fatalf("loop run 1 %s: NextRefreshAfter = %v, want about now+%v", label, next, metaADWriteRetryDelay)
		}
	}
	requireRetryLater("loop run 1", before, after, 2)
	if got := exec.RefreshCalls(); got != 2 {
		t.Fatalf("Refresh calls = %d, want 2 (a pending write never mints)", got)
	}
	if got := len(store.markerSaves()); got != 2 {
		t.Fatalf("failed disable save attempts = %d, want 2", got)
	}

	// Third attempt succeeds and the disable is written.
	runLoop()
	metaADWrRequireDisabled(t, metaADGet(t, m, metaADPrimaryID), metaADReasonMintRejected)
	if got := exec.RefreshCalls(); got != 2 {
		t.Fatalf("Refresh calls = %d, want 2", got)
	}
	if got := len(store.markerSaves()); got != 3 {
		t.Fatalf("disable save attempts = %d, want 3 (2 failed + 1 written)", got)
	}
}

func TestMetaAutoDisableWrite_PersistFailureOnlyBlocksPersistRequiredUpdates(t *testing.T) {
	store := &metaADWrStore{}
	exec := newMetaADTestExecutor()
	m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, exec, false,
		metaADWrFileAuth(metaADPrimaryID, "live-key", "dca:primary"))
	edit := func(label string) func(a *Auth) error {
		return func(a *Auth) error {
			if a.Attributes == nil {
				a.Attributes = map[string]string{}
			}
			a.Attributes["label"] = label
			return nil
		}
	}

	// Control: an ordinary failing save is still published in memory.
	store.failNext(1)
	if _, _, err := m.Modify(context.Background(), metaADPrimaryID, 0, edit("ordinary")); err != nil {
		t.Fatalf("ordinary Modify error = %v, want the save failure to stay non-fatal", err)
	}
	if got := metaADGet(t, m, metaADPrimaryID).Attributes["label"]; got != "ordinary" {
		t.Fatalf("label = %q, an ordinary update must be published despite the failed save", got)
	}

	// The persist-required context is the only difference.
	store.failNext(1)
	if _, ok, err := m.Modify(metaADPersistContext(), metaADPrimaryID, 0, edit("required")); err == nil || ok {
		t.Fatalf("persist-required Modify = (%v, %v), want an error and no commit", ok, err)
	}
	if got := metaADGet(t, m, metaADPrimaryID).Attributes["label"]; got != "ordinary" {
		t.Fatalf("label = %q, a persist-required update must not be published when the save fails", got)
	}
}

func TestMetaAutoDisableWrite_SwitchOffNeverWrites(t *testing.T) {
	t.Run("switch turned off after confirmation", func(t *testing.T) {
		store := &metaADWrStore{}
		exec := newMetaADTestExecutor()
		m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, exec, false,
			metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary"))
		metaADWrCraftConfirmed(t, m, metaADPrimaryID, metaADReasonMintRejected)
		m.SetConfig(metaADWrConfig(false, 0))

		m.metaAutoDisableWrite(metaADPrimaryID, metaADWrEpisode(t, m, metaADPrimaryID))
		// With the switch off the confirmed credential is released and selectable again.
		metaADWrRequireReleased(t, m, store, metaADPrimaryID)
		metaADConfirmDue(m, metaADPrimaryID)

		if got := metaADGet(t, m, metaADPrimaryID); got.Disabled {
			t.Fatalf("disabled with the switch off")
		}
		if saves := store.markerSaves(); len(saves) != 0 {
			t.Fatalf("saves with markers = %d, want 0", len(saves))
		}
		if stamps := metaADWrLimiterStamps(m); stamps != 0 {
			t.Fatalf("limiter stamps = %d, want 0", stamps)
		}
	})

	t.Run("switch off from the start", func(t *testing.T) {
		store := &metaADWrStore{}
		exec := newMetaADTestExecutor("dead-key-0")
		exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)}, metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
		m := newMetaADWrManager(t, metaADWrConfig(false, 0), store, exec, true,
			metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary"), metaADBackup())
		if _, err := metaADExecute(m, metaADModelA); err != nil {
			t.Fatalf("Execute: %v", err)
		}
		metaADConfirmDue(m, metaADPrimaryID)
		if got := metaADGet(t, m, metaADPrimaryID); got.Disabled || got.metaAD.state != "" {
			t.Fatalf("disabled=%v metaAD=%+v, want the legacy behaviour", got.Disabled, got.metaAD)
		}
		if saves := store.markerSaves(); len(saves) != 0 {
			t.Fatalf("saves with markers = %d, want 0", len(saves))
		}
	})
}

func TestMetaAutoDisableWrite_NoDeadlockWhileSaveIsBlocked(t *testing.T) {
	store := &metaADWrStore{}
	exec := newMetaADTestExecutor("dead-key-0")
	exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)}, metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
	other := metaADBackup()
	m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, exec, true,
		metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary"), other)
	if _, err := metaADExecute(m, metaADModelA); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	metaADRequireTracked(t, metaADGet(t, m, metaADPrimaryID), metaADStatePending, metaADReasonMintRejected)

	// The write is triggered from the background refresh path while the save is blocked.
	store.armBlock()
	refreshDone := make(chan struct{})
	go func() {
		defer close(refreshDone)
		metaADConfirmDue(m, metaADPrimaryID)
	}()
	<-store.entered

	// A 401 result for the same credential waits for the gate; MarkResult only ever enters
	// pending, it never writes, so this is the "concurrent MarkResult" combination.
	markDone := make(chan struct{})
	go func() {
		defer close(markDone)
		m.MarkResult(context.Background(), Result{
			AuthID: metaADPrimaryID, Provider: "meta", Model: metaADModelA, Success: false,
			Error: &Error{HTTPStatus: http.StatusUnauthorized, Message: "key rejected"},
		})
	}()
	// An update of an unrelated credential must not be blocked by the pending save.
	updateDone := make(chan error, 1)
	go func() {
		upd := metaADBackup()
		upd.Attributes = map[string]string{"label": "unrelated"}
		_, err := m.Update(context.Background(), upd)
		updateDone <- err
	}()
	select {
	case err := <-updateDone:
		if err != nil {
			t.Fatalf("unrelated Update: %v", err)
		}
	case <-time.After(30 * time.Second): // failure guard only
		t.Fatalf("unrelated Update blocked behind the disable save")
	}
	for i := 0; i < 100; i++ {
		runtime.Gosched()
	}

	close(store.release)
	for name, ch := range map[string]chan struct{}{"refresh": refreshDone, "MarkResult": markDone} {
		select {
		case <-ch:
		case <-time.After(30 * time.Second): // failure guard only
			t.Fatalf("%s did not finish: deadlock", name)
		}
	}

	got := metaADGet(t, m, metaADPrimaryID)
	if !got.Disabled || got.Metadata[metaADKeyDisabledBy] != metaADDisabledBy {
		t.Fatalf("disabled=%v metadata=%v, want the written disable to stand", got.Disabled, got.Metadata)
	}
	if got.metaAD.state != "" {
		t.Fatalf("raw metaAD = %+v, want cleared", got.metaAD)
	}
	stamps := map[any]bool{}
	for _, meta := range store.markerSaves() {
		stamps[meta[metaADKeyDisabledAt]] = true
	}
	if len(stamps) != 1 {
		t.Fatalf("distinct disabled_at values = %d, want the markers written once", len(stamps))
	}
}

func TestMetaAutoDisableWrite_ForcedRefreshOfPendingCredentialEndsInWrite(t *testing.T) {
	store := &metaADWrStore{}
	exec := newMetaADTestExecutor("dead-key-0")
	exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)}, metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
	m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, exec, true,
		metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary"), metaADBackup())
	if _, err := metaADExecute(m, metaADModelA); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	metaADRequireTracked(t, metaADGet(t, m, metaADPrimaryID), metaADStatePending, metaADReasonMintRejected)

	if _, err := m.ForceRefreshAuth(context.Background(), metaADPrimaryID); err == nil {
		t.Fatalf("ForceRefreshAuth error = nil, want the mint rejection")
	}
	metaADWrRequireDisabled(t, metaADGet(t, m, metaADPrimaryID), metaADReasonMintRejected)
	metaADWrRequireSingleWrite(t, store, metaADReasonMintRejected)
}

func TestMetaAutoDisableWrite_HourlyCapHoldsBackAndRecovers(t *testing.T) {
	hook := setupTestLoggerHook(t)
	store := &metaADWrStore{}
	exec := newMetaADTestExecutor()
	ids := []string{"a1-newkey", "b2-mint", "c3-nodca", "d4-mint"}
	reasons := map[string]string{
		"a1-newkey": metaADReasonNewKeyRejected,
		"b2-mint":   metaADReasonMintRejected,
		"c3-nodca":  metaADReasonNoDCAToken,
		"d4-mint":   metaADReasonMintRejected,
	}
	var auths []*Auth
	for _, id := range ids {
		dca := "dca:" + id
		if id == "c3-nodca" {
			dca = ""
		}
		auths = append(auths, metaADWrFileAuth(id, "dead-"+id, dca))
	}
	m := newMetaADWrManager(t, metaADWrConfig(true, 1), store, exec, false, auths...)
	for _, id := range ids {
		metaADWrCraftConfirmed(t, m, id, reasons[id])
	}

	capErrors := func() int {
		n := 0
		for _, e := range hook.AllEntries() {
			if e.Level == log.ErrorLevel && strings.Contains(e.Message, "hourly disable cap") {
				n++
			}
		}
		return n
	}

	before := time.Now()
	for _, id := range ids {
		m.metaAutoDisableWrite(id, metaADWrEpisode(t, m, id))
	}
	after := time.Now()

	first := metaADGet(t, m, "a1-newkey")
	if !first.Disabled {
		t.Fatalf("the first credential must be disabled")
	}
	if len(store.markerSaves()) != 1 {
		t.Fatalf("saves with markers = %d, want 1 (the cap holds the others back)", len(store.markerSaves()))
	}
	for _, id := range ids[1:] {
		got := metaADGet(t, m, id)
		state, reason, _, ok := got.MetaAutoDisableStatus()
		if !ok || state != metaADStateCapped || reason != reasons[id] {
			t.Fatalf("%s: status = (%q, %q, %v), want (capped, %s)", id, state, reason, ok, reasons[id])
		}
		if got.Disabled {
			t.Fatalf("%s: disabled over the cap", id)
		}
		metaADRequireDueIn(t, got, before, after, metaADCapRetryDelay)
		if hasUnauthorizedAuthFailure(got) {
			t.Fatalf("%s: hasUnauthorizedAuthFailure = true", id)
		}
		if want := fmt.Sprintf("meta auto-disable capped (%s)", reasons[id]); got.StatusMessage != want {
			t.Fatalf("%s: StatusMessage = %q, want %q", id, got.StatusMessage, want)
		}
		if blocked, _, _ := isAuthBlockedForModel(got, metaADModelA, time.Now()); !blocked {
			t.Fatalf("%s: not blocked", id)
		}
	}
	if got := capErrors(); got != 1 {
		t.Fatalf("cap error log lines = %d, want exactly 1 per window", got)
	}

	// A second cap hit inside the window stays silent; after capLoggedAt ages out it logs again.
	m.metaADLimiter.mu.Lock()
	m.metaADLimiter.capLoggedAt = time.Now().Add(-2 * metaADCapWindow)
	m.metaADLimiter.mu.Unlock()
	metaADWrCraftConfirmed(t, m, "d4-mint", metaADReasonMintRejected)
	m.metaAutoDisableWrite("d4-mint", metaADWrEpisode(t, m, "d4-mint"))
	if got := capErrors(); got != 2 {
		t.Fatalf("cap error log lines after the log window aged = %d, want 2", got)
	}

	// The window passes: the cap no longer applies and the capped credentials are confirmed again.
	m.SetConfig(metaADWrConfig(true, 10))
	m.metaADLimiter.mu.Lock()
	for i := range m.metaADLimiter.stamps {
		m.metaADLimiter.stamps[i] = m.metaADLimiter.stamps[i].Add(-2 * metaADCapWindow)
	}
	m.metaADLimiter.mu.Unlock()
	for _, id := range ids[1:] {
		metaADMakeDue(m, id)
	}

	// b2-mint (mint_rejected) mints again first; the rejection then disables it.
	exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
	m.refreshAuth(context.Background(), "b2-mint")
	if got := exec.RefreshCalls(); got != 1 {
		t.Fatalf("Refresh calls after b2-mint = %d, want 1 (a capped mint_rejected credential mints again)", got)
	}
	metaADWrRequireDisabledNoPriority(t, metaADGet(t, m, "b2-mint"), metaADReasonMintRejected)

	// c3-nodca (no_dca_token) is written without a mint.
	m.refreshAuth(context.Background(), "c3-nodca")
	if got := exec.RefreshCalls(); got != 1 {
		t.Fatalf("Refresh calls after c3-nodca = %d, want still 1", got)
	}
	metaADWrRequireDisabledNoPriority(t, metaADGet(t, m, "c3-nodca"), metaADReasonNoDCAToken)

	// d4-mint's mint now succeeds: it is restored, not disabled.
	exec.enqueue(metaADRefreshResult{})
	m.refreshAuth(context.Background(), "d4-mint")
	if got := exec.RefreshCalls(); got != 2 {
		t.Fatalf("Refresh calls after d4-mint = %d, want 2", got)
	}
	restored := metaADGet(t, m, "d4-mint")
	metaADRequireNotTracked(t, restored)
	if restored.Disabled || restored.Unavailable {
		t.Fatalf("d4-mint: disabled=%v unavailable=%v, want restored", restored.Disabled, restored.Unavailable)
	}
	if blocked, _, _ := isAuthBlockedForModel(restored, metaADModelA, time.Now()); blocked {
		t.Fatalf("d4-mint still blocked after the successful mint")
	}
}

// metaADWrRequireDisabledNoPriority checks the disabled end state for credentials built
// without the shared fixture's unrelated metadata keys.
func metaADWrRequireDisabledNoPriority(t *testing.T, a *Auth, reason string) {
	t.Helper()
	if !a.Disabled || a.Status != StatusDisabled || a.StatusMessage != fmt.Sprintf("disabled (meta %s)", reason) {
		t.Fatalf("%s: disabled=%v status=%v message=%q", a.ID, a.Disabled, a.Status, a.StatusMessage)
	}
	if a.Metadata["disabled"] != true || a.Metadata[metaADKeyDisabledBy] != metaADDisabledBy || a.Metadata[metaADKeyReason] != reason {
		t.Fatalf("%s: markers = %v", a.ID, a.Metadata)
	}
	metaADWrRequireTimestamp(t, a.Metadata[metaADKeyDisabledAt])
	if _, _, _, ok := a.MetaAutoDisableStatus(); ok || a.metaAD.state != "" || metaADEligible(a) {
		t.Fatalf("%s: still tracked or eligible: %+v", a.ID, a.metaAD)
	}
	if !a.NextRefreshAfter.IsZero() || !a.NextRetryAfter.IsZero() || a.LastError != nil || a.Unavailable {
		t.Fatalf("%s: nextRefresh=%v nextRetry=%v lastErr=%v unavailable=%v, want all cleared", a.ID, a.NextRefreshAfter, a.NextRetryAfter, a.LastError, a.Unavailable)
	}
	for _, model := range []string{metaADModelA, metaADModelB, metaADModelC, ""} {
		if blocked, _, _ := isAuthBlockedForModel(a, model, time.Now()); !blocked {
			t.Fatalf("%s: not blocked for model %q", a.ID, model)
		}
	}
}

func TestMetaAutoDisableWrite_ZeroMaxPerHourMeansTwenty(t *testing.T) {
	store := &metaADWrStore{}
	exec := newMetaADTestExecutor()
	var auths []*Auth
	for i := 0; i < 21; i++ {
		auths = append(auths, metaADWrFileAuth(fmt.Sprintf("cred-%02d", i), fmt.Sprintf("dead-%02d", i), fmt.Sprintf("dca:%02d", i)))
	}
	m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, exec, false, auths...)
	for _, a := range auths {
		metaADWrCraftConfirmed(t, m, a.ID, metaADReasonNewKeyRejected)
		m.metaAutoDisableWrite(a.ID, metaADWrEpisode(t, m, a.ID))
	}
	disabled, capped := 0, 0
	for _, a := range auths {
		got := metaADGet(t, m, a.ID)
		if got.Disabled {
			disabled++
		} else if state, _, _, ok := got.MetaAutoDisableStatus(); ok && state == metaADStateCapped {
			capped++
		}
	}
	if disabled != 20 || capped != 1 {
		t.Fatalf("disabled=%d capped=%d, want 20 and 1", disabled, capped)
	}
}

func TestMetaAutoDisableWrite_LimiterReserveRelease(t *testing.T) {
	var l metaADLimiter
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	if ok, logCap := l.reserve(base, 2); !ok || logCap {
		t.Fatalf("first reserve = (%v, %v), want (true, false)", ok, logCap)
	}
	if ok, _ := l.reserve(base.Add(time.Minute), 2); !ok {
		t.Fatalf("second reserve refused")
	}
	// Full: the first refusal in the window logs, the next ones do not.
	if ok, logCap := l.reserve(base.Add(2*time.Minute), 2); ok || !logCap {
		t.Fatalf("third reserve = (%v, %v), want (false, true)", ok, logCap)
	}
	if ok, logCap := l.reserve(base.Add(3*time.Minute), 2); ok || logCap {
		t.Fatalf("fourth reserve = (%v, %v), want (false, false): logged once per window", ok, logCap)
	}
	// Releasing a slot reopens it; releasing an unknown stamp changes nothing.
	l.release(base.Add(time.Minute))
	l.release(base.Add(99 * time.Hour))
	if len(l.stamps) != 1 {
		t.Fatalf("stamps after release = %d, want 1", len(l.stamps))
	}
	if ok, _ := l.reserve(base.Add(4*time.Minute), 2); !ok {
		t.Fatalf("reserve after release refused")
	}
	// Full again; the log flag re-arms only once its own window has passed.
	if ok, logCap := l.reserve(base.Add(5*time.Minute), 2); ok || logCap {
		t.Fatalf("reserve = (%v, %v), want refused and silent inside the logged window", ok, logCap)
	}
	// The window slides: base ages out, base+4m stays.
	if ok, _ := l.reserve(base.Add(metaADCapWindow+time.Second), 2); !ok {
		t.Fatalf("reserve after the first stamp aged out refused")
	}
	if len(l.stamps) != 2 {
		t.Fatalf("stamps after pruning = %d, want 2", len(l.stamps))
	}
	if ok, logCap := l.reserve(base.Add(metaADCapWindow+3*time.Minute), 2); ok || !logCap {
		t.Fatalf("reserve = (%v, %v), want refused and logged again after the log window", ok, logCap)
	}
}

func TestMetaAutoDisableWrite_EarlyChecksKeepCapAndGateOutOfIrrelevantWrites(t *testing.T) {
	hook := setupTestLoggerHook(t)
	store := &metaADWrStore{}
	exec := newMetaADTestExecutor()

	written := metaADWrFileAuth("a1-written", "dead-a1", "dca:a1")
	pending := metaADWrFileAuth("b2-pending", "dead-b2", "dca:b2")
	healthy := metaADWrFileAuth("c3-healthy", "live-c3", "dca:c3")
	configKey := metaADWrFileAuth("d4-config", "dead-d4", "dca:d4")
	configKey.Attributes = map[string]string{"api_key": "dead-d4", AttributeSource: "config:meta[abc]"}
	disabled := metaADWrFileAuth("e5-disabled", "dead-e5", "dca:e5")
	switchOff := metaADWrFileAuth("f6-switchoff", "dead-f6", "dca:f6")
	m := newMetaADWrManager(t, metaADWrConfig(true, 1), store, exec, false, written, pending, healthy, configKey, disabled, switchOff)

	// Fill the one-slot cap with a real write.
	metaADWrCraftConfirmed(t, m, written.ID, metaADReasonNewKeyRejected)
	m.metaAutoDisableWrite(written.ID, metaADWrEpisode(t, m, written.ID))
	if !metaADGet(t, m, written.ID).Disabled || metaADWrLimiterStamps(m) != 1 {
		t.Fatalf("precondition: first credential not written or cap not full (stamps=%d)", metaADWrLimiterStamps(m))
	}
	baseSaves := len(store.markerSaves())

	// (a) tracked but not confirmed
	m.mu.Lock()
	metaADEnterPending(m.auths[pending.ID], metaADReasonMintRejected, time.Now())
	m.mu.Unlock()
	// (c) not eligible: a config key and an already disabled credential, both carrying a confirmed state
	metaADWrCraftConfirmed(t, m, configKey.ID, metaADReasonMintRejected)
	metaADWrCraftConfirmed(t, m, disabled.ID, metaADReasonMintRejected)
	m.mu.Lock()
	m.auths[disabled.ID].Disabled = true
	m.auths[disabled.ID].Status = StatusDisabled
	m.mu.Unlock()
	// (d) tracked and confirmed, but the switch is off
	metaADWrCraftConfirmed(t, m, switchOff.ID, metaADReasonMintRejected)

	type snap struct {
		disabled bool
		status   Status
		message  string
		next     time.Time
		ad       metaAutoDisableState
	}
	snapshot := func(id string) snap {
		a := metaADGet(t, m, id)
		return snap{a.Disabled, a.Status, a.StatusMessage, a.NextRefreshAfter, a.metaAD}
	}
	ids := []string{pending.ID, healthy.ID, configKey.ID, disabled.ID}
	before := map[string]snap{}
	for _, id := range ids {
		before[id] = snapshot(id)
	}

	for _, id := range ids[:4] {
		m.metaAutoDisableWrite(id, metaADWrEpisode(t, m, id))
	}
	m.SetConfig(metaADWrConfig(false, 1))
	m.metaAutoDisableWrite(switchOff.ID, metaADWrEpisode(t, m, switchOff.ID))

	// (d) With the switch off the confirmed credential is released from the feature: tracking
	// and its own block are gone, nothing is written, and it never reached the cap.
	released := metaADGet(t, m, switchOff.ID)
	if released.metaAD.state != "" || released.Unavailable || released.Status == StatusError || released.LastError != nil ||
		released.StatusMessage != "" || !released.NextRefreshAfter.IsZero() || released.Disabled || hasUnauthorizedAuthFailure(released) {
		t.Fatalf("switch-off credential not released: %+v", released)
	}
	if blocked, _, _ := isAuthBlockedForModel(released, metaADModelA, time.Now()); blocked {
		t.Fatalf("released credential still blocked")
	}

	for _, id := range ids {
		if got := snapshot(id); got != before[id] {
			t.Fatalf("%s changed by an irrelevant write: before=%+v after=%+v", id, before[id], got)
		}
		if state, _, _, ok := metaADGet(t, m, id).MetaAutoDisableStatus(); ok && state == metaADStateCapped {
			t.Fatalf("%s turned capped by a write that had nothing to write", id)
		}
	}
	if stamps := metaADWrLimiterStamps(m); stamps != 1 {
		t.Fatalf("limiter stamps = %d, want 1: an irrelevant write consumed or leaked a slot", stamps)
	}
	m.metaADLimiter.mu.Lock()
	capLogged := m.metaADLimiter.capLoggedAt
	m.metaADLimiter.mu.Unlock()
	if !capLogged.IsZero() {
		t.Fatalf("capLoggedAt = %v, want zero: the cap was consulted", capLogged)
	}
	for _, e := range hook.AllEntries() {
		if e.Level == log.ErrorLevel {
			t.Fatalf("unexpected error log line: %s", e.Message)
		}
	}
	if got := len(store.markerSaves()); got != baseSaves {
		t.Fatalf("marker saves = %d, want %d", got, baseSaves)
	}
}

func TestMetaAutoDisableWrite_ConfirmedStateIsExposedAsPendingEvenAfterRetryOrCapped(t *testing.T) {
	requirePending := func(t *testing.T, a *Auth, reason string) {
		t.Helper()
		state, got, _, ok := a.MetaAutoDisableStatus()
		if !ok || state != metaADStatePending || got != reason {
			t.Fatalf("status = (%q, %q, %v), want (pending, %s, true)", state, got, ok, reason)
		}
		if want := fmt.Sprintf("meta auto-disable pending (%s)", reason); a.StatusMessage != want {
			t.Fatalf("StatusMessage = %q, want %q", a.StatusMessage, want)
		}
		if !a.metaAD.confirmed || a.Disabled {
			t.Fatalf("confirmed=%v disabled=%v, want confirmed and not disabled", a.metaAD.confirmed, a.Disabled)
		}
	}

	t.Run("retry then rejected with a failing save", func(t *testing.T) {
		store := &metaADWrStore{}
		exec := newMetaADTestExecutor("dead-key-0")
		exec.enqueue(
			metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)}, // request path -> pending
			metaADRefreshResult{err: metaADNetworkErr()},                     // confirmation -> retry
			metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)}, // next confirmation -> rejected
		)
		m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, exec, true,
			metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary"), metaADBackup())
		if _, err := metaADExecute(m, metaADModelA); err != nil {
			t.Fatalf("Execute: %v", err)
		}
		metaADConfirmDue(m, metaADPrimaryID)
		metaADRequireTracked(t, metaADGet(t, m, metaADPrimaryID), metaADStateRetry, metaADReasonMintRejected)

		store.failNext(1)
		metaADConfirmDue(m, metaADPrimaryID)
		requirePending(t, metaADGet(t, m, metaADPrimaryID), metaADReasonMintRejected)
	})

	for _, reason := range []string{metaADReasonNewKeyRejected, metaADReasonNoDCAToken} {
		t.Run("capped "+reason+" settled with a failing save", func(t *testing.T) {
			store := &metaADWrStore{}
			exec := newMetaADTestExecutor()
			dca := "dca:b2"
			if reason == metaADReasonNoDCAToken {
				dca = ""
			}
			m := newMetaADWrManager(t, metaADWrConfig(true, 1), store, exec, false,
				metaADWrFileAuth("a1-written", "dead-a1", "dca:a1"), metaADWrFileAuth("b2-capped", "dead-b2", dca))
			metaADWrCraftConfirmed(t, m, "a1-written", metaADReasonNewKeyRejected)
			m.metaAutoDisableWrite("a1-written", metaADWrEpisode(t, m, "a1-written"))
			metaADWrCraftConfirmed(t, m, "b2-capped", reason)
			m.metaAutoDisableWrite("b2-capped", metaADWrEpisode(t, m, "b2-capped"))
			state, _, _, ok := metaADGet(t, m, "b2-capped").MetaAutoDisableStatus()
			if !ok || state != metaADStateCapped {
				t.Fatalf("precondition: state = %q ok=%v, want capped", state, ok)
			}

			// The window passes and the cap grows; the settle's save fails.
			m.SetConfig(metaADWrConfig(true, 10))
			m.metaADLimiter.mu.Lock()
			m.metaADLimiter.stamps = nil
			m.metaADLimiter.mu.Unlock()
			store.failNext(1)
			metaADConfirmDue(m, "b2-capped")
			requirePending(t, metaADGet(t, m, "b2-capped"), reason)
		})
	}
}

func TestMetaAutoDisableWrite_AfterSkippedWriteReinstallsDeadlineOnlyWhileConfirmed(t *testing.T) {
	cases := []struct {
		name  string
		setup func(m *Manager, live *Auth, state *metaAutoDisableState)
		check func(t *testing.T, live *Auth, oldDue, start, end time.Time)
	}{
		{"confirmed with an expired deadline gets a fresh retry time",
			func(_ *Manager, live *Auth, _ *metaAutoDisableState) {
				live.NextRefreshAfter = time.Now().Add(-time.Second)
			},
			func(t *testing.T, live *Auth, oldDue, start, end time.Time) {
				metaADRequireDueIn(t, live, start, end, metaADWriteRetryDelay)
				if live.NextRefreshAfter.Equal(oldDue) {
					t.Fatalf("deadline unchanged: %v", oldDue)
				}
			}},
		{"confirmed with a future deadline in the same episode also gets a fresh one",
			func(_ *Manager, live *Auth, _ *metaAutoDisableState) {
				live.NextRefreshAfter = time.Now().Add(3 * time.Minute)
			},
			func(t *testing.T, live *Auth, oldDue, start, end time.Time) {
				metaADRequireDueIn(t, live, start, end, metaADWriteRetryDelay)
				if live.NextRefreshAfter.Equal(oldDue) {
					t.Fatalf("deadline unchanged: %v", oldDue)
				}
			}},
		{"not confirmed is left alone",
			func(_ *Manager, live *Auth, _ *metaAutoDisableState) {
				live.metaAD.confirmed = false
				live.NextRefreshAfter = time.Now().Add(-time.Second)
			},
			func(t *testing.T, live *Auth, oldDue, _, _ time.Time) {
				if !live.NextRefreshAfter.Equal(oldDue) || live.metaAD.state == "" {
					t.Fatalf("deadline %v -> %v state=%q, want untouched", oldDue, live.NextRefreshAfter, live.metaAD.state)
				}
			}},
		{"different episode is left alone",
			func(_ *Manager, live *Auth, state *metaAutoDisableState) {
				live.NextRefreshAfter = time.Now().Add(-time.Second)
				state.since = state.since.Add(time.Second)
			},
			func(t *testing.T, live *Auth, oldDue, _, _ time.Time) {
				if !live.NextRefreshAfter.Equal(oldDue) {
					t.Fatalf("deadline %v -> %v, want unchanged for another episode", oldDue, live.NextRefreshAfter)
				}
			}},
		{"disabled credential with leftover state is cleared",
			func(_ *Manager, live *Auth, _ *metaAutoDisableState) {
				live.Disabled = true
				live.Status = StatusDisabled
			},
			func(t *testing.T, live *Auth, _, _, _ time.Time) {
				if live.metaAD.state != "" {
					t.Fatalf("raw metaAD = %+v, want cleared", live.metaAD)
				}
			}},
		{"switch off releases the credential",
			func(m *Manager, live *Auth, _ *metaAutoDisableState) {
				live.NextRefreshAfter = time.Now().Add(-time.Second)
				m.SetConfig(metaADWrConfig(false, 0))
			},
			func(t *testing.T, live *Auth, _, _, _ time.Time) {
				if live.metaAD.state != "" || live.Unavailable || live.LastError != nil || live.Status == StatusError ||
					!live.NextRefreshAfter.IsZero() || hasUnauthorizedAuthFailure(live) {
					t.Fatalf("not released: %+v", live)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exec := newMetaADTestExecutor()
			m := newMetaADWrManager(t, metaADWrConfig(true, 0), nil, exec, false,
				metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary"))
			metaADWrCraftConfirmed(t, m, metaADPrimaryID, metaADReasonMintRejected)
			// Single goroutine: the setup may call SetConfig, which takes m.mu itself.
			live := m.auths[metaADPrimaryID]
			state := live.metaAD
			tc.setup(m, live, &state)
			oldDue := live.NextRefreshAfter

			start := time.Now()
			m.metaADAfterSkippedWrite(metaADPrimaryID, state, start)
			end := time.Now()

			m.mu.RLock()
			defer m.mu.RUnlock()
			tc.check(t, m.auths[metaADPrimaryID], oldDue, start, end)
		})
	}
}

// metaADWrRunJob drives one refresh job for id the way the background loop does. It is
// safe to call from a goroutine (it reports with t.Errorf).
func metaADWrRunJob(t *testing.T, m *Manager, id string) {
	ctx := context.Background()
	l := newAuthAutoRefreshLoop(m, time.Second, 1)
	l.handleDueAuth(ctx, time.Now(), id)
	select {
	case job := <-l.jobs:
		if m.beginRefreshJob(ctx, job) {
			_, _ = m.refreshAuthForRequestAtEpoch(ctx, job.id, "", job.registrationEpoch)
		}
		m.finishRefreshJob(job, time.Time{}, false)
	default:
		t.Errorf("no refresh job enqueued for %s", id)
	}
}

// metaADWrRequireReleased asserts the credential fell back to ordinary, selectable state.
func metaADWrRequireReleased(t *testing.T, m *Manager, store *metaADWrStore, id string) {
	t.Helper()
	got := metaADGet(t, m, id)
	if hasUnauthorizedAuthFailure(got) {
		t.Fatalf("hasUnauthorizedAuthFailure = true: the synthetic 401 was left terminal")
	}
	if got.Unavailable || got.Status == StatusError || got.LastError != nil || got.StatusMessage != "" {
		t.Fatalf("unavailable=%v status=%v lastErr=%v message=%q, want the block lifted", got.Unavailable, got.Status, got.LastError, got.StatusMessage)
	}
	if got.metaAD.state != "" || got.Disabled || !got.NextRefreshAfter.IsZero() {
		t.Fatalf("metaAD=%+v disabled=%v nextRefresh=%v, want released", got.metaAD, got.Disabled, got.NextRefreshAfter)
	}
	if saves := store.markerSaves(); len(saves) != 0 {
		t.Fatalf("saves with markers = %d, want 0", len(saves))
	}
	if stamps := metaADWrLimiterStamps(m); stamps != 0 {
		t.Fatalf("limiter stamps = %d, want 0", stamps)
	}
	if blocked, _, _ := isAuthBlockedForModel(got, metaADModelA, time.Now()); blocked {
		t.Fatalf("released credential still blocked")
	}
	if next, schedule := nextRefreshCheckAt(time.Now(), got, time.Second); schedule || !next.IsZero() {
		t.Fatalf("nextRefreshCheckAt = (%v, %v), want (zero, false)", next, schedule)
	}
}

func TestMetaAutoDisableWrite_SkippedWriteWithSwitchOffReleasesCredentialThroughJobLifecycle(t *testing.T) {
	t.Run("switch_off_before_the_write_check", func(t *testing.T) {
		for _, reason := range []string{metaADReasonNewKeyRejected, metaADReasonNoDCAToken} {
			t.Run(reason, func(t *testing.T) {
				store := &metaADWrStore{}
				exec := newMetaADTestExecutor()
				dca := "dca:primary"
				if reason == metaADReasonNoDCAToken {
					dca = ""
				}
				m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, exec, true,
					metaADWrFileAuth(metaADPrimaryID, "dead-key-0", dca))
				m.mu.Lock()
				metaADEnterPending(m.auths[metaADPrimaryID], reason, time.Now())
				m.auths[metaADPrimaryID].NextRefreshAfter = time.Now().Add(-time.Second)
				m.mu.Unlock()

				release := m.lockAuthMutation(metaADPrimaryID)
				done := make(chan struct{})
				go func() {
					defer close(done)
					metaADWrRunJob(t, m, metaADPrimaryID)
				}()
				// Settle waits for the gate; the switch goes off before it can mark and write.
				metaADWrWaitForGateWaiter(m, metaADPrimaryID, 1)
				m.SetConfig(metaADWrConfig(false, 0))
				release()
				<-done

				metaADWrRequireReleased(t, m, store, metaADPrimaryID)
			})
		}
	})

	t.Run("switch_off_while_modify_waits_for_the_gate", func(t *testing.T) {
		store := &metaADWrStore{}
		exec := newMetaADTestExecutor()
		m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, exec, true,
			metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary"))
		metaADWrCraftConfirmed(t, m, metaADPrimaryID, metaADReasonMintRejected)
		metaADMakeDue(m, metaADPrimaryID)

		release := m.lockAuthMutation(metaADPrimaryID)
		done := make(chan struct{})
		go func() {
			defer close(done)
			metaADWrRunJob(t, m, metaADPrimaryID)
		}()
		// The credential is confirmed, so Settle skips the gate; the write reserves a slot and
		// Modify waits for the gate.
		metaADWrWaitForGateWaiter(m, metaADPrimaryID, 1)
		m.SetConfig(metaADWrConfig(false, 0))
		release()
		<-done

		metaADWrRequireReleased(t, m, store, metaADPrimaryID)
		if got := exec.RefreshCalls(); got != 0 {
			t.Fatalf("Refresh calls = %d, want 0", got)
		}
	})
}

func TestMetaAutoDisableWrite_SettleAndWriteIgnoreAnotherEpisode(t *testing.T) {
	// replaceWithNewEpisode re-logs the credential in (new key) while the caller holds the
	// gate and starts a fresh pending episode for it. It returns the time it entered pending.
	replaceWithNewEpisode := func(t *testing.T, m *Manager, confirmed bool) time.Time {
		t.Helper()
		replacement := metaADWrFileAuth(metaADPrimaryID, "login-key-9", "dca:login")
		committed, ok, persistCooldown, err := m.updateInternalLocked(context.Background(), nil, replacement, updateModeReplace)
		if err != nil || !ok {
			t.Fatalf("updateInternalLocked = (%v, %v)", ok, err)
		}
		entered := time.Now()
		m.mu.Lock()
		live := m.auths[metaADPrimaryID]
		metaADEnterPending(live, metaADReasonNewKeyRejected, entered)
		if confirmed {
			metaADMarkConfirmed(live, entered)
		}
		m.mu.Unlock()
		m.finishAuthUpdate(context.Background(), committed, persistCooldown)
		return entered
	}
	requireUntouchedEpisode := func(t *testing.T, m *Manager, store *metaADWrStore, entered time.Time, confirmed bool) {
		t.Helper()
		got := metaADGet(t, m, metaADPrimaryID)
		if got.Disabled || got.metaAD.confirmed != confirmed || got.metaAD.state != metaADStatePending {
			t.Fatalf("disabled=%v confirmed=%v state=%q, want the new episode untouched", got.Disabled, got.metaAD.confirmed, got.metaAD.state)
		}
		delay := metaADConfirmDelay
		if confirmed {
			delay = metaADWriteRetryDelay
		}
		if got.NextRefreshAfter.Before(entered.Add(delay-time.Second)) || got.NextRefreshAfter.After(entered.Add(delay+time.Second)) {
			t.Fatalf("NextRefreshAfter = %v, want about %v after the new episode began", got.NextRefreshAfter, delay)
		}
		if saves := store.markerSaves(); len(saves) != 0 {
			t.Fatalf("saves with markers = %d, want 0", len(saves))
		}
		if stamps := metaADWrLimiterStamps(m); stamps != 0 {
			t.Fatalf("limiter stamps = %d, want 0", stamps)
		}
	}
	newPending := func(t *testing.T) (*Manager, *metaADWrStore, metaADEpisode) {
		store := &metaADWrStore{}
		m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, newMetaADTestExecutor(), false,
			metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary"))
		m.mu.Lock()
		metaADEnterPending(m.auths[metaADPrimaryID], metaADReasonNewKeyRejected, time.Now())
		m.mu.Unlock()
		return m, store, metaADWrEpisode(t, m, metaADPrimaryID)
	}

	t.Run("Settle", func(t *testing.T) {
		m, store, episodeA := newPending(t)
		release := m.lockAuthMutation(metaADPrimaryID)
		entered := replaceWithNewEpisode(t, m, false)
		release()
		m.metaAutoDisableSettle(metaADPrimaryID, episodeA)
		requireUntouchedEpisode(t, m, store, entered, false)
	})

	t.Run("Write", func(t *testing.T) {
		m, store, episodeA := newPending(t)
		release := m.lockAuthMutation(metaADPrimaryID)
		entered := replaceWithNewEpisode(t, m, true)
		release()
		m.metaAutoDisableWrite(metaADPrimaryID, episodeA)
		requireUntouchedEpisode(t, m, store, entered, true)
	})

	t.Run("job snapshot taken before the re-login", func(t *testing.T) {
		m, store, _ := newPending(t)
		m.mu.Lock()
		m.auths[metaADPrimaryID].NextRefreshAfter = time.Now().Add(-time.Second)
		m.mu.Unlock()

		release := m.lockAuthMutation(metaADPrimaryID)
		done := make(chan struct{})
		go func() {
			defer close(done)
			metaADWrRunJob(t, m, metaADPrimaryID)
		}()
		// The job holds episode A and waits in Settle for the gate.
		metaADWrWaitForGateWaiter(m, metaADPrimaryID, 1)
		entered := replaceWithNewEpisode(t, m, false)
		release()
		<-done

		got := metaADGet(t, m, metaADPrimaryID)
		if got.Disabled || got.metaAD.confirmed || got.metaAD.state != metaADStatePending {
			t.Fatalf("disabled=%v confirmed=%v state=%q, want the new episode untouched by the old job", got.Disabled, got.metaAD.confirmed, got.metaAD.state)
		}
		if got.NextRefreshAfter.IsZero() {
			t.Fatalf("NextRefreshAfter is zero: the new pending episode lost its deadline (entered %v)", entered)
		}
		if saves := store.markerSaves(); len(saves) != 0 {
			t.Fatalf("saves with markers = %d, want 0", len(saves))
		}
		if stamps := metaADWrLimiterStamps(m); stamps != 0 {
			t.Fatalf("limiter stamps = %d, want 0", stamps)
		}
	})
}

func TestMetaAutoDisableWrite_RefreshErrorForAnEpisodeStartedMeanwhileIsNotConfirmed(t *testing.T) {
	store := &metaADWrStore{}
	exec := newMetaADTestExecutor()
	exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
	m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, exec, false,
		metaADWrFileAuth(metaADPrimaryID, "live-key", "dca:primary"))

	release, wait := metaADBlockedRefresh(t, exec, func() error {
		_, err := m.ForceRefreshAuth(context.Background(), metaADPrimaryID)
		return err
	})
	// While the forced mint is in flight, a concurrent 401 starts a pending episode.
	entered := time.Now()
	m.mu.Lock()
	metaADEnterPending(m.auths[metaADPrimaryID], metaADReasonMintRejected, entered)
	m.mu.Unlock()
	release()
	if err := wait(); err == nil {
		t.Fatalf("ForceRefreshAuth error = nil, want the mint error")
	}

	got := metaADGet(t, m, metaADPrimaryID)
	metaADRequireTracked(t, got, metaADStatePending, metaADReasonMintRejected)
	if got.metaAD.confirmed || got.Disabled {
		t.Fatalf("confirmed=%v disabled=%v, a failure from before the episode must not confirm it", got.metaAD.confirmed, got.Disabled)
	}
	if got.NextRefreshAfter.Before(entered.Add(metaADConfirmDelay-time.Second)) || got.NextRefreshAfter.After(entered.Add(metaADConfirmDelay+time.Second)) {
		t.Fatalf("NextRefreshAfter = %v, want about %v after the episode began", got.NextRefreshAfter, metaADConfirmDelay)
	}
	if saves := store.markerSaves(); len(saves) != 0 {
		t.Fatalf("saves with markers = %d, want 0", len(saves))
	}
}

func TestMetaAutoDisableWrite_FailedSaveAfterLocalWriteKeepsCapSlot(t *testing.T) {
	// A store that writes the watched local file first and uploads afterwards can fail the
	// Save after the local copy already carries the disable. Refunding the slot would let
	// the local disables exceed the cap.
	store := &metaADWrStore{localThenFail: true}
	exec := newMetaADTestExecutor()
	m := newMetaADWrManager(t, metaADWrConfig(true, 1), store, exec, false,
		metaADWrFileAuth("a1-first", "dead-a1", "dca:a1"), metaADWrFileAuth("b2-second", "dead-b2", "dca:b2"))
	metaADWrCraftConfirmed(t, m, "a1-first", metaADReasonNewKeyRejected)
	metaADWrCraftConfirmed(t, m, "b2-second", metaADReasonNewKeyRejected)

	before := time.Now()
	m.metaAutoDisableWrite("a1-first", metaADWrEpisode(t, m, "a1-first"))
	after := time.Now()
	a := metaADGet(t, m, "a1-first")
	if a.Disabled {
		t.Fatalf("the disable was published although the save failed")
	}
	if !a.metaAD.confirmed {
		t.Fatalf("a1-first lost its confirmed verdict")
	}
	metaADRequireDueIn(t, a, before, after, metaADWriteRetryDelay)
	if stamps := metaADWrLimiterStamps(m); stamps != 1 {
		t.Fatalf("limiter stamps = %d, want 1: a failed save must keep its slot", stamps)
	}

	m.metaAutoDisableWrite("b2-second", metaADWrEpisode(t, m, "b2-second"))
	b := metaADGet(t, m, "b2-second")
	if state, _, _, ok := b.MetaAutoDisableStatus(); !ok || state != metaADStateCapped {
		t.Fatalf("b2-second state = %q ok=%v, want capped by the kept slot", state, ok)
	}
	store.mu.Lock()
	local := len(store.localFiles)
	store.mu.Unlock()
	if local != 1 {
		t.Fatalf("credentials with a local disable = %d, want 1 (the cap)", local)
	}
}

func TestMetaAutoDisableWrite_ForcedRefreshOfConfirmedCredentialWritesOnlyOnRejection(t *testing.T) {
	cases := []struct {
		name   string
		result metaADRefreshResult
		want   string // "keep", "written" or "rescued"
	}{
		{"network error", metaADRefreshResult{err: metaADNetworkErr()}, "keep"},
		{"mint 503", metaADRefreshResult{err: metaADMintErr(http.StatusServiceUnavailable)}, "keep"},
		{"mint 500", metaADRefreshResult{err: metaADMintErr(http.StatusInternalServerError)}, "keep"},
		{"mint 401", metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)}, "written"},
		{"mint 403", metaADRefreshResult{err: metaADMintErr(http.StatusForbidden)}, "written"},
		{"mint success", metaADRefreshResult{}, "rescued"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &metaADWrStore{}
			exec := newMetaADTestExecutor("dead-key-0")
			exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)}, metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
			m := newMetaADWrManager(t, metaADWrConfig(true, 0), store, exec, true,
				metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary"), metaADBackup())
			if _, err := metaADExecute(m, metaADModelA); err != nil {
				t.Fatalf("Execute: %v", err)
			}
			// The confirmation reaches its verdict but the first save fails: confirmed, unsaved.
			store.failNext(1)
			metaADConfirmDue(m, metaADPrimaryID)
			unsaved := metaADGet(t, m, metaADPrimaryID)
			if !unsaved.metaAD.confirmed || unsaved.Disabled {
				t.Fatalf("precondition: confirmed=%v disabled=%v", unsaved.metaAD.confirmed, unsaved.Disabled)
			}
			stampsBefore := metaADWrLimiterStamps(m)
			savesBefore := len(store.markerSaves())

			exec.enqueue(tc.result)
			_, _ = m.ForceRefreshAuth(context.Background(), metaADPrimaryID)

			got := metaADGet(t, m, metaADPrimaryID)
			switch tc.want {
			case "keep":
				metaADRequireTracked(t, got, metaADStatePending, metaADReasonMintRejected)
				if !got.metaAD.confirmed || got.Disabled {
					t.Fatalf("confirmed=%v disabled=%v, a transient failure must keep the verdict", got.metaAD.confirmed, got.Disabled)
				}
				if got.NextRefreshAfter.IsZero() || !got.NextRefreshAfter.Equal(unsaved.NextRefreshAfter) {
					t.Fatalf("NextRefreshAfter %v -> %v, want non-zero and unchanged", unsaved.NextRefreshAfter, got.NextRefreshAfter)
				}
				if after := len(store.markerSaves()); after != savesBefore {
					t.Fatalf("marker saves %d -> %d, want no write", savesBefore, after)
				}
				if stamps := metaADWrLimiterStamps(m); stamps != stampsBefore {
					t.Fatalf("limiter stamps %d -> %d, want no new slot", stampsBefore, stamps)
				}
			case "written":
				metaADWrRequireDisabledNoPriority(t, got, metaADReasonMintRejected)
			case "rescued":
				metaADRequireNotTracked(t, got)
				if got.Disabled || got.Unavailable {
					t.Fatalf("disabled=%v unavailable=%v, want a rescued credential", got.Disabled, got.Unavailable)
				}
				if blocked, _, _ := isAuthBlockedForModel(got, metaADModelA, time.Now()); blocked {
					t.Fatalf("rescued credential still blocked")
				}
				if after := len(store.markerSaves()); after != savesBefore {
					t.Fatalf("marker saves %d -> %d, want nothing written", savesBefore, after)
				}
			}
		})
	}
}

func TestMetaAutoDisableWrite_StatusAccessorIgnoresDisabledCredential(t *testing.T) {
	now := time.Now()
	build := func(enter func(a *Auth)) *Auth {
		a := metaADWrFileAuth(metaADPrimaryID, "dead-key-0", "dca:primary")
		metaADEnterPending(a, metaADReasonMintRejected, now)
		enter(a)
		return a
	}
	tracked := map[string]*Auth{
		metaADStatePending: build(func(*Auth) {}),
		metaADStateRetry:   build(func(a *Auth) { metaADEnterRetry(a, now) }),
		metaADStateCapped:  build(func(a *Auth) { metaADEnterCapped(a, now) }),
	}
	for want, a := range tracked {
		t.Run(want, func(t *testing.T) {
			state, reason, since, ok := a.MetaAutoDisableStatus()
			if !ok || state != want || reason != metaADReasonMintRejected || !since.Equal(now) {
				t.Fatalf("status = (%q, %q, %v, %v), want (%s, mint_rejected, %v, true)", state, reason, since, ok, want, now)
			}
			disabled := a.Clone()
			disabled.Disabled = true
			if _, _, _, ok := disabled.MetaAutoDisableStatus(); ok {
				t.Fatalf("Disabled credential reports ok=true")
			}
			statusDisabled := a.Clone()
			statusDisabled.Status = StatusDisabled
			if _, _, _, ok := statusDisabled.MetaAutoDisableStatus(); ok {
				t.Fatalf("StatusDisabled credential reports ok=true")
			}
			changed := a.Clone()
			changed.Metadata["api_key"] = "another-key"
			changed.Metadata["access_token"] = "another-key"
			if _, _, _, ok := changed.MetaAutoDisableStatus(); ok {
				t.Fatalf("credential with a changed key reports ok=true")
			}
		})
	}
	var nilAuth *Auth
	if _, _, _, ok := nilAuth.MetaAutoDisableStatus(); ok {
		t.Fatalf("nil receiver reports ok=true")
	}
}
