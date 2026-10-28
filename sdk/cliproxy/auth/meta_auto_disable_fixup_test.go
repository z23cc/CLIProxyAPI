package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"

	metaauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/meta"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Fixtures for the Meta auto-disable review fixup tests. Every helper is prefixed
// metaADFx so it cannot clash with the helpers of meta_auto_disable_test.go.

const (
	metaADFxPrimaryID = "aa-fx-primary"
	metaADFxBackupID  = "bb-fx-backup"
	metaADFxModelA    = "fx-model-a"
	metaADFxModelB    = "fx-model-b"
	metaADFxModelC    = "fx-model-c"
)

var metaADFxModels = []string{metaADFxModelA, metaADFxModelB, metaADFxModelC, ""}

func metaADFxMintErr(status int) error {
	return fmt.Errorf("meta executor: mint API key failed: %w", &metaauth.MintError{Status: status, Body: "x"})
}

// metaADFxExecutor is a Meta executor double. Execute answers 401 for keys in invalid.
// Refresh pops its outcome from queue (nil entry or empty queue: mint a live key) and
// writes every slot the real MetaExecutor.Refresh writes, starting from the auth it got.
type metaADFxExecutor struct {
	mu           sync.Mutex
	invalid      map[string]struct{}
	queue        []error
	refreshCalls int
	mintSeq      int
	calls        []string
	prepareCalls int
}

func newMetaADFxExecutor(invalid ...string) *metaADFxExecutor {
	e := &metaADFxExecutor{invalid: make(map[string]struct{})}
	for _, k := range invalid {
		e.invalid[k] = struct{}{}
	}
	return e
}

func (e *metaADFxExecutor) Identifier() string { return "meta" }

func (e *metaADFxExecutor) enqueue(errs ...error) {
	e.mu.Lock()
	e.queue = append(e.queue, errs...)
	e.mu.Unlock()
}

func (e *metaADFxExecutor) run(auth *Auth) ([]byte, error) {
	key := metaADKey(auth)
	e.mu.Lock()
	e.calls = append(e.calls, auth.ID)
	_, bad := e.invalid[key]
	e.mu.Unlock()
	if bad {
		return nil, &Error{HTTPStatus: http.StatusUnauthorized, Message: "key rejected"}
	}
	return []byte(auth.ID + ":" + key), nil
}

func (e *metaADFxExecutor) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	payload, err := e.run(auth)
	return cliproxyexecutor.Response{Payload: payload}, err
}

func (e *metaADFxExecutor) ExecuteStream(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	payload, err := e.run(auth)
	if err != nil {
		return nil, err
	}
	ch := make(chan cliproxyexecutor.StreamChunk, 1)
	ch <- cliproxyexecutor.StreamChunk{Payload: payload}
	close(ch)
	return &cliproxyexecutor.StreamResult{Chunks: ch}, nil
}

func (e *metaADFxExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	e.mu.Lock()
	e.refreshCalls++
	var outcome error
	if len(e.queue) > 0 {
		outcome = e.queue[0]
		e.queue = e.queue[1:]
	}
	dca := metaADDCAToken(auth)
	if outcome == nil && dca != "" {
		e.mintSeq++
	}
	seq := e.mintSeq
	e.mu.Unlock()
	if outcome != nil {
		return nil, outcome
	}
	if dca == "" {
		return auth, nil
	}
	key := fmt.Sprintf("fx-minted-%d", seq)
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = key
	auth.Metadata["api_key"] = key
	auth.Metadata["dca_token"] = dca
	auth.Metadata["last_refresh"] = time.Now().Format(time.RFC3339)
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes["base_url"] = "https://meta.example.invalid"
	auth.Attributes["api_key"] = key
	auth.Attributes["access_token"] = key
	return auth, nil
}

func (e *metaADFxExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, &Error{HTTPStatus: http.StatusNotImplemented, Message: "not implemented"}
}

func (e *metaADFxExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func (e *metaADFxExecutor) refreshCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.refreshCalls
}

func (e *metaADFxExecutor) callsFor(id string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, c := range e.calls {
		if c == id {
			n++
		}
	}
	return n
}

// metaADFxPreparer mints in PrepareRequestAuth while the auth has a dca_token and no key.
type metaADFxPreparer struct{ *metaADFxExecutor }

func (e *metaADFxPreparer) ShouldPrepareRequestAuth(auth *Auth) bool {
	return metaADKey(auth) == "" && metaADDCAToken(auth) != ""
}

func (e *metaADFxPreparer) PrepareRequestAuth(ctx context.Context, auth *Auth) (*Auth, error) {
	e.mu.Lock()
	e.prepareCalls++
	e.mu.Unlock()
	return e.Refresh(ctx, auth)
}

// metaADFxStore is a Store double whose Save can block (block) or fail (fail).
type metaADFxStore struct {
	mu      sync.Mutex
	block   bool
	fail    bool
	saving  chan struct{}
	release chan struct{}
}

func newMetaADFxStore() *metaADFxStore {
	return &metaADFxStore{saving: make(chan struct{}), release: make(chan struct{})}
}

func (s *metaADFxStore) setFail(v bool) {
	s.mu.Lock()
	s.fail = v
	s.mu.Unlock()
}

func (s *metaADFxStore) armBlock() {
	s.mu.Lock()
	s.block = true
	s.mu.Unlock()
}

func (s *metaADFxStore) List(context.Context) ([]*Auth, error) { return nil, nil }
func (s *metaADFxStore) Delete(context.Context, string) error  { return nil }

// Save ignores ctx on purpose: a competing mutation cancels the persist context, and the
// test needs the save to stay in flight until it is released.
func (s *metaADFxStore) Save(context.Context, *Auth) (string, error) {
	s.mu.Lock()
	fail, block := s.fail, s.block
	s.block = false
	s.mu.Unlock()
	if fail {
		return "", errors.New("fx store: save failed")
	}
	if block {
		close(s.saving)
		<-s.release
	}
	return "", nil
}

func metaADFxSwitch(enabled bool) *internalconfig.Config {
	return &internalconfig.Config{Routing: internalconfig.RoutingConfig{MetaAutoDisable: internalconfig.MetaAutoDisableConfig{Enabled: enabled}}}
}

func metaADFxKeyAuth(id, key, dca string) *Auth {
	md := map[string]any{"type": "meta", "access_token": key, "api_key": key}
	if dca != "" {
		md["dca_token"] = dca
	}
	return &Auth{ID: id, Provider: "meta", Metadata: md}
}

func metaADFxPrimary() *Auth { return metaADFxKeyAuth(metaADFxPrimaryID, "dead-key-0", "dca:primary") }
func metaADFxBackup() *Auth  { return metaADFxKeyAuth(metaADFxBackupID, "good-key", "dca:backup") }

func newMetaADFxManager(t *testing.T, enabled bool, store Store, exec ProviderExecutor, auths ...*Auth) *Manager {
	t.Helper()
	m := NewManager(store, nil, nil)
	m.RegisterExecutor(exec)
	m.SetConfig(metaADFxSwitch(enabled))
	reg := registry.GetGlobalRegistry()
	models := []*registry.ModelInfo{{ID: metaADFxModelA}, {ID: metaADFxModelB}, {ID: metaADFxModelC}}
	for _, a := range auths {
		id := a.ID
		reg.RegisterClient(id, "meta", models)
		t.Cleanup(func() { reg.UnregisterClient(id) })
		if _, err := m.Register(context.Background(), a); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}
	return m
}

func metaADFxExecute(m *Manager, model string) (cliproxyexecutor.Response, error) {
	return m.Execute(context.Background(), []string{"meta"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
}

func metaADFxGet(t *testing.T, m *Manager, id string) *Auth {
	t.Helper()
	a, ok := m.GetByID(id)
	if !ok || a == nil {
		t.Fatalf("auth %s missing", id)
	}
	return a
}

func metaADFxRaw(m *Manager, id string) metaAutoDisableState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.auths[id].metaAD
}

func metaADFxMakeDue(m *Manager, id string) {
	m.mu.Lock()
	m.auths[id].NextRefreshAfter = time.Now().Add(-time.Second)
	m.mu.Unlock()
}

// metaADFxRequireTracked checks the state plus the invariants that hold whenever a
// credential is tracked: non-zero NextRefreshAfter, no terminal-unauthorized reading,
// blocked for every model.
func metaADFxRequireTracked(t *testing.T, a *Auth, wantState, wantReason string) {
	t.Helper()
	state, reason, since, ok := a.MetaAutoDisableStatus()
	if !ok || state != wantState || reason != wantReason || since.IsZero() {
		t.Fatalf("MetaAutoDisableStatus = (%q, %q, %v, %v), want (%q, %q, non-zero, true)", state, reason, since, ok, wantState, wantReason)
	}
	if a.NextRefreshAfter.IsZero() {
		t.Fatalf("NextRefreshAfter is zero while tracked")
	}
	if hasUnauthorizedAuthFailure(a) {
		t.Fatalf("hasUnauthorizedAuthFailure = true while tracked")
	}
	if !a.Unavailable || a.Status != StatusError {
		t.Fatalf("Unavailable=%v Status=%v, want the blocked shape", a.Unavailable, a.Status)
	}
	now := time.Now()
	for _, model := range metaADFxModels {
		if blocked, _, _ := isAuthBlockedForModel(a, model, now); !blocked {
			t.Fatalf("tracked auth not blocked for model %q", model)
		}
	}
}

func metaADFxRequireNotTracked(t *testing.T, a *Auth) {
	t.Helper()
	if state, reason, _, ok := a.MetaAutoDisableStatus(); ok {
		t.Fatalf("auth is tracked (%q, %q), want not tracked", state, reason)
	}
}

func metaADFxRequireSelectable(t *testing.T, a *Auth, models ...string) {
	t.Helper()
	if a.Unavailable {
		t.Fatalf("Unavailable = true, want selectable")
	}
	now := time.Now()
	for _, model := range models {
		if blocked, reason, _ := isAuthBlockedForModel(a, model, now); blocked {
			t.Fatalf("auth blocked for model %q (reason %v)", model, reason)
		}
	}
}

// metaADFxEnterPendingViaRequest drives the request path: the primary's key is rejected,
// the mint is rejected with status, the request fails over to the backup.
func metaADFxEnterPendingViaRequest(t *testing.T, store Store, status int) (*Manager, *metaADFxExecutor) {
	t.Helper()
	exec := newMetaADFxExecutor("dead-key-0")
	exec.enqueue(metaADFxMintErr(status))
	m := newMetaADFxManager(t, true, store, exec, metaADFxPrimary(), metaADFxBackup())
	resp, err := metaADFxExecute(m, metaADFxModelA)
	if err != nil {
		t.Fatalf("Execute error = %v, want success via backup", err)
	}
	if got := string(resp.Payload); got != metaADFxBackupID+":good-key" {
		t.Fatalf("payload = %q, want backup response", got)
	}
	metaADFxRequireTracked(t, metaADFxGet(t, m, metaADFxPrimaryID), metaADStatePending, metaADReasonMintRejected)
	return m, exec
}

// F5: a transition must not be lost to a concurrent credential save.
func TestMetaAutoDisableFixup_TransitionSurvivesConcurrentSave(t *testing.T) {
	cases := []struct {
		name       string
		dca        string
		wantReason string
		transition func(m *Manager, target *Auth)
	}{
		{
			name:       "prepare_error",
			dca:        "dca:primary",
			wantReason: metaADReasonMintRejected,
			transition: func(m *Manager, target *Auth) {
				m.metaAutoDisableOnPrepareError(target, metaADFxMintErr(http.StatusUnauthorized))
			},
		},
		{
			name:       "unauthorized_no_dca",
			dca:        "",
			wantReason: metaADReasonNoDCAToken,
			transition: func(m *Manager, target *Auth) {
				if !m.metaAutoDisableOnUnauthorized(target, "") {
					t.Errorf("metaAutoDisableOnUnauthorized = false, want true for a credential without dca_token")
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newMetaADFxStore()
			exec := newMetaADFxExecutor()
			m := newMetaADFxManager(t, true, store, exec, metaADFxKeyAuth(metaADFxPrimaryID, "live-key", tc.dca))
			target := metaADFxGet(t, m, metaADFxPrimaryID)

			store.armBlock()
			unrelated := metaADFxKeyAuth(metaADFxPrimaryID, "live-key", tc.dca)
			unrelated.Attributes = map[string]string{"label": "unrelated change"}
			doneA := make(chan error, 1)
			go func() {
				_, err := m.Update(context.Background(), unrelated)
				doneA <- err
			}()
			<-store.saving

			doneB := make(chan struct{})
			go func() {
				defer close(doneB)
				tc.transition(m, target)
			}()
			// B either blocks on the mutation gate (waiters >= 1) or, if the gate is
			// missing, finishes while the save is still in flight.
			state := m.metadataPersistPreempt(metaADFxPrimaryID)
		wait:
			for {
				state.mu.Lock()
				waiters := state.waiters
				state.mu.Unlock()
				if waiters >= 1 {
					break wait
				}
				select {
				case <-doneB:
					break wait
				default:
					runtime.Gosched()
				}
			}
			close(store.release)
			if err := <-doneA; err != nil {
				t.Fatalf("Update: %v", err)
			}
			<-doneB

			got := metaADFxGet(t, m, metaADFxPrimaryID)
			metaADFxRequireTracked(t, got, metaADStatePending, tc.wantReason)
			if got.Attributes["label"] != "unrelated change" {
				t.Fatalf("the concurrent save was lost: attributes = %v", got.Attributes)
			}
		})
	}
}

func metaADFxDCAOnlyAuth() *Auth {
	return &Auth{
		ID:       metaADFxPrimaryID,
		Provider: "meta",
		Metadata: map[string]any{"type": "meta", "dca_token": "dca:primary", "access_token": "dca:primary"},
	}
}

// F6: a DCA-only credential rejected on its first mint is fully restored by a confirmed mint.
func TestMetaAutoDisableFixup_FirstMintRejectionFullyRestoredByConfirmation(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusUnauthorized} {
		t.Run(fmt.Sprintf("mint_%d", status), func(t *testing.T) {
			exec := &metaADFxPreparer{metaADFxExecutor: newMetaADFxExecutor()}
			exec.enqueue(metaADFxMintErr(status))
			m := newMetaADFxManager(t, true, nil, exec, metaADFxDCAOnlyAuth(), metaADFxBackup())

			if _, err := metaADFxExecute(m, metaADFxModelA); err != nil {
				t.Fatalf("Execute error = %v, want success via backup", err)
			}
			pending := metaADFxGet(t, m, metaADFxPrimaryID)
			metaADFxRequireTracked(t, pending, metaADStatePending, metaADReasonMintRejected)

			// The rejection left a rejection error, a cooldown and a model state behind.
			if pending.LastError == nil || pending.LastError.StatusCode() != status {
				t.Fatalf("precondition: auth LastError = %+v, want status %d", pending.LastError, status)
			}
			if pending.StatusMessage == "" {
				t.Fatalf("precondition: StatusMessage is empty")
			}
			if pending.NextRetryAfter.IsZero() {
				t.Fatalf("precondition: auth NextRetryAfter is zero, want the cooldown MarkResult left")
			}
			stA := pending.ModelStates[metaADFxModelA]
			if stA == nil || !stA.Unavailable || stA.LastError == nil || stA.LastError.StatusCode() != status || stA.NextRetryAfter.IsZero() {
				t.Fatalf("precondition: model-a state = %+v, want a %d state with a cooldown", stA, status)
			}

			// An unrelated quota state on another model must survive the restore.
			recoverAt := time.Now().Add(10 * time.Minute)
			m.mu.Lock()
			m.auths[metaADFxPrimaryID].ModelStates[metaADFxModelC] = &ModelState{
				Status:         StatusError,
				StatusMessage:  "quota exceeded",
				Unavailable:    true,
				NextRetryAfter: recoverAt,
				LastError:      &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota exceeded"},
				Quota:          QuotaState{Exceeded: true, Reason: "quota exceeded", NextRecoverAt: recoverAt},
			}
			m.mu.Unlock()

			metaADFxMakeDue(m, metaADFxPrimaryID)
			m.refreshAuth(context.Background(), metaADFxPrimaryID)

			if got := exec.refreshCount(); got != 2 {
				t.Fatalf("Refresh calls = %d, want 2 (rejected first mint + confirmation)", got)
			}
			got := metaADFxGet(t, m, metaADFxPrimaryID)
			metaADFxRequireNotTracked(t, got)
			if got.Unavailable || got.Status != StatusActive {
				t.Fatalf("Unavailable=%v Status=%v, want available active", got.Unavailable, got.Status)
			}
			if !got.NextRetryAfter.IsZero() || !got.NextRefreshAfter.IsZero() {
				t.Fatalf("NextRetryAfter=%v NextRefreshAfter=%v, want both zero", got.NextRetryAfter, got.NextRefreshAfter)
			}
			if got.LastError != nil || got.StatusMessage != "" {
				t.Fatalf("LastError=%+v StatusMessage=%q, want cleared", got.LastError, got.StatusMessage)
			}
			if st := got.ModelStates[metaADFxModelA]; st != nil && (st.Unavailable || !st.NextRetryAfter.IsZero() || st.LastError != nil) {
				t.Fatalf("model-a rejection state not reset: %+v", st)
			}
			stC := got.ModelStates[metaADFxModelC]
			if stC == nil || !stC.Unavailable || !stC.NextRetryAfter.Equal(recoverAt) || !stC.Quota.Exceeded || stC.LastError == nil || stC.LastError.HTTPStatus != http.StatusTooManyRequests {
				t.Fatalf("unrelated quota state was touched: %+v", stC)
			}
			now := time.Now()
			for _, model := range []string{metaADFxModelA, metaADFxModelB, ""} {
				if blocked, _, _ := isAuthBlockedForModel(got, model, now); blocked {
					t.Fatalf("restored auth still blocked for model %q", model)
				}
			}
			before := exec.callsFor(metaADFxPrimaryID)
			for i := 0; i < 2; i++ {
				if _, err := metaADFxExecute(m, metaADFxModelA); err != nil {
					t.Fatalf("Execute after restore: %v", err)
				}
			}
			if exec.callsFor(metaADFxPrimaryID) <= before {
				t.Fatalf("primary was not selected after the restore")
			}
		})
	}
}

// metaADFxRunDueJob drives one due auth through the real job lifecycle, exactly as the
// refresh loop's worker does, and reports whether a job was dispatched.
func metaADFxRunDueJob(t *testing.T, m *Manager, l *authAutoRefreshLoop, id string) bool {
	t.Helper()
	ctx := context.Background()
	l.handleDueAuth(ctx, time.Now(), id)
	select {
	case job := <-l.jobs:
		if m.beginRefreshJob(ctx, job) {
			_, _ = m.refreshAuthForRequestAtEpoch(ctx, job.id, "", job.registrationEpoch)
		}
		m.finishRefreshJob(job, time.Time{}, false)
		return true
	default:
		return false
	}
}

// F7: a failed save after a successful confirmation mint must not strand the credential.
func TestMetaAutoDisableFixup_SaveFailureAfterConfirmationMintKeepsConfirmationTime(t *testing.T) {
	store := newMetaADFxStore()
	m, exec := metaADFxEnterPendingViaRequest(t, store, http.StatusUnauthorized)
	l := newAuthAutoRefreshLoop(m, time.Second, 1)

	store.setFail(true)
	metaADFxMakeDue(m, metaADFxPrimaryID)
	before := time.Now()
	if !metaADFxRunDueJob(t, m, l, metaADFxPrimaryID) {
		t.Fatalf("no refresh job was dispatched for the due confirmation")
	}
	after := time.Now()

	if got := exec.refreshCount(); got != 2 {
		t.Fatalf("Refresh calls = %d, want 2", got)
	}
	got := metaADFxGet(t, m, metaADFxPrimaryID)
	metaADFxRequireTracked(t, got, metaADStateRetry, metaADReasonMintRejected)
	if got.NextRefreshAfter.Before(before.Add(metaADRetryDelay(1)-time.Second)) || got.NextRefreshAfter.After(after.Add(metaADRetryDelay(1)+time.Second)) {
		t.Fatalf("NextRefreshAfter = %v, want about now+%v", got.NextRefreshAfter, metaADRetryDelay(1))
	}
	if key := metaADKey(got); key != "dead-key-0" {
		t.Fatalf("installed key = %q, want the old key after the failed save", key)
	}
	probe := time.Now().Add(10 * time.Minute)
	next, ok := nextRefreshCheckAt(probe, got, time.Second)
	if !ok || next.IsZero() || next.After(probe) {
		t.Fatalf("nextRefreshCheckAt = (%v, %v), want a schedule that is not past the probe time", next, ok)
	}

	// The store recovers: the next confirmation restores the credential.
	store.setFail(false)
	metaADFxMakeDue(m, metaADFxPrimaryID)
	if !metaADFxRunDueJob(t, m, l, metaADFxPrimaryID) {
		t.Fatalf("no refresh job was dispatched for the retry")
	}
	got = metaADFxGet(t, m, metaADFxPrimaryID)
	metaADFxRequireNotTracked(t, got)
	metaADFxRequireSelectable(t, got, metaADFxModels...)
	if key := metaADKey(got); key != "fx-minted-2" {
		t.Fatalf("installed key = %q, want the key minted by the retry", key)
	}
}

// F8: a plain Update keeps or drops the in-memory state consistently.
func TestMetaAutoDisableFixup_UpdateKeepsOrDropsState(t *testing.T) {
	t.Run("same_credential_keeps_state", func(t *testing.T) {
		m, _ := metaADFxEnterPendingViaRequest(t, nil, http.StatusUnauthorized)
		prev := metaADFxGet(t, m, metaADFxPrimaryID).NextRefreshAfter

		if _, err := m.Update(context.Background(), metaADFxPrimary()); err != nil {
			t.Fatalf("Update: %v", err)
		}
		got := metaADFxGet(t, m, metaADFxPrimaryID)
		metaADFxRequireTracked(t, got, metaADStatePending, metaADReasonMintRejected)
		if got.NextRefreshAfter.Before(prev) {
			t.Fatalf("NextRefreshAfter = %v moved back from %v", got.NextRefreshAfter, prev)
		}
		if m.shouldRefresh(got, time.Now()) {
			t.Fatalf("shouldRefresh = true right after an Update: the confirmation delay was bypassed")
		}
	})

	t.Run("changed_dca_drops_state", func(t *testing.T) {
		m, _ := metaADFxEnterPendingViaRequest(t, nil, http.StatusUnauthorized)
		if _, err := m.Update(context.Background(), metaADFxKeyAuth(metaADFxPrimaryID, "dead-key-0", "dca:other")); err != nil {
			t.Fatalf("Update: %v", err)
		}
		if raw := metaADFxRaw(m, metaADFxPrimaryID); raw.state != "" {
			t.Fatalf("raw state = %+v, want dropped", raw)
		}
		got := metaADFxGet(t, m, metaADFxPrimaryID)
		metaADFxRequireNotTracked(t, got)
		// The key itself is still the one upstream rejected (RejectedAccessToken), so
		// selection may still skip it for that reason; only the feature's own block and
		// the blocked shape it applied must be gone.
		if metaADBlocks(got) || got.Unavailable || got.Status == StatusError || !got.NextRefreshAfter.IsZero() ||
			got.LastError != nil || got.StatusMessage != "" {
			t.Fatalf("blocked shape left behind: unavailable=%v status=%v nextRefresh=%v lastErr=%+v msg=%q",
				got.Unavailable, got.Status, got.NextRefreshAfter, got.LastError, got.StatusMessage)
		}
	})

	t.Run("changed_key_drops_state", func(t *testing.T) {
		m, _ := metaADFxEnterPendingViaRequest(t, nil, http.StatusUnauthorized)
		if _, err := m.Update(context.Background(), metaADFxKeyAuth(metaADFxPrimaryID, "relogin-key", "dca:primary")); err != nil {
			t.Fatalf("Update: %v", err)
		}
		if raw := metaADFxRaw(m, metaADFxPrimaryID); raw.state != "" {
			t.Fatalf("raw state = %+v, want dropped", raw)
		}
		got := metaADFxGet(t, m, metaADFxPrimaryID)
		metaADFxRequireNotTracked(t, got)
		metaADFxRequireSelectable(t, got, metaADFxModels...)
	})

	t.Run("disabling_update_drops_state", func(t *testing.T) {
		m, _ := metaADFxEnterPendingViaRequest(t, nil, http.StatusUnauthorized)
		disabled := metaADFxPrimary()
		disabled.Disabled = true
		disabled.Status = StatusDisabled
		if _, err := m.Update(context.Background(), disabled); err != nil {
			t.Fatalf("Update: %v", err)
		}
		if raw := metaADFxRaw(m, metaADFxPrimaryID); raw.state != "" {
			t.Fatalf("raw state = %+v, want dropped", raw)
		}
		got := metaADFxGet(t, m, metaADFxPrimaryID)
		metaADFxRequireNotTracked(t, got)
		if !got.Disabled {
			t.Fatalf("auth is not disabled after the disabling Update")
		}
	})
}

// N1: the DCA lookup follows the executor, not authHasRefreshCredential.
func TestMetaAutoDisableFixup_DCALookupFollowsExecutor(t *testing.T) {
	forms := []struct {
		name string
		auth func() *Auth
	}{
		{"access_token_dca_prefix", func() *Auth {
			return &Auth{ID: metaADFxPrimaryID, Provider: "meta", Metadata: map[string]any{
				"type": "meta", "api_key": "dead-key-0", "access_token": "dca:old-format",
			}}
		}},
		{"storage_only_dca", func() *Auth {
			return &Auth{ID: metaADFxPrimaryID, Provider: "meta",
				Metadata: map[string]any{"type": "meta", "api_key": "dead-key-0", "access_token": "dead-key-0"},
				Storage:  &metaauth.MetaTokenStorage{APIKey: "dead-key-0", AccessToken: "dead-key-0", DCAToken: "dca:storage"},
			}
		}},
	}
	for _, form := range forms {
		t.Run(form.name+"/mint_succeeds", func(t *testing.T) {
			exec := newMetaADFxExecutor("dead-key-0")
			m := newMetaADFxManager(t, true, nil, exec, form.auth(), metaADFxBackup())
			resp, err := metaADFxExecute(m, metaADFxModelA)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if got := string(resp.Payload); got != metaADFxPrimaryID+":fx-minted-1" {
				t.Fatalf("payload = %q, want the primary served with the re-minted key", got)
			}
			if got := exec.refreshCount(); got != 1 {
				t.Fatalf("Refresh calls = %d, want 1", got)
			}
			metaADFxRequireNotTracked(t, metaADFxGet(t, m, metaADFxPrimaryID))
		})
		t.Run(form.name+"/mint_rejected", func(t *testing.T) {
			exec := newMetaADFxExecutor("dead-key-0")
			exec.enqueue(metaADFxMintErr(http.StatusUnauthorized))
			m := newMetaADFxManager(t, true, nil, exec, form.auth(), metaADFxBackup())
			resp, err := metaADFxExecute(m, metaADFxModelA)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if got := string(resp.Payload); got != metaADFxBackupID+":good-key" {
				t.Fatalf("payload = %q, want the backup", got)
			}
			if got := exec.refreshCount(); got != 1 {
				t.Fatalf("Refresh calls = %d, want 1", got)
			}
			metaADFxRequireTracked(t, metaADFxGet(t, m, metaADFxPrimaryID), metaADStatePending, metaADReasonMintRejected)
		})
		t.Run(form.name+"/switch_off", func(t *testing.T) {
			exec := newMetaADFxExecutor("dead-key-0")
			m := newMetaADFxManager(t, false, nil, exec, form.auth(), metaADFxBackup())
			resp, err := metaADFxExecute(m, metaADFxModelA)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if got := string(resp.Payload); got != metaADFxBackupID+":good-key" {
				t.Fatalf("payload = %q, want the backup", got)
			}
			if got := exec.refreshCount(); got != 0 {
				t.Fatalf("Refresh calls = %d, want 0 with the switch off", got)
			}
			metaADFxRequireNotTracked(t, metaADFxGet(t, m, metaADFxPrimaryID))
		})
	}
}

// N2: key and dca_token lookups mirror the executor, including a Storage-only credential.
func TestMetaAutoDisableFixup_KeyAndDCALookupsMirrorExecutor(t *testing.T) {
	type slots struct {
		attrs   map[string]string
		meta    map[string]any
		storage *metaauth.MetaTokenStorage
	}
	build := func(s slots) *Auth {
		a := &Auth{ID: "n2", Provider: "meta", Attributes: s.attrs, Metadata: s.meta}
		if s.storage != nil {
			a.Storage = s.storage
		}
		return a
	}
	store := func(api, access, dca string) *metaauth.MetaTokenStorage {
		return &metaauth.MetaTokenStorage{APIKey: api, AccessToken: access, DCAToken: dca}
	}
	keyCases := []struct {
		name string
		in   slots
		want string
	}{
		{"attr_api_key_first", slots{attrs: map[string]string{"api_key": "k-attr", "access_token": "k-attr-at"}, meta: map[string]any{"api_key": "k-md"}, storage: store("k-st", "", "")}, "k-attr"},
		{"attr_access_token_over_metadata", slots{attrs: map[string]string{"access_token": "k-attr-at"}, meta: map[string]any{"api_key": "k-md"}}, "k-attr-at"},
		{"attr_api_key_dca_skipped", slots{attrs: map[string]string{"api_key": "dca:x", "access_token": "k-attr-at"}}, "k-attr-at"},
		{"attr_all_dca_falls_to_metadata", slots{attrs: map[string]string{"api_key": "dca:x", "access_token": "dca:y"}, meta: map[string]any{"api_key": "k-md"}}, "k-md"},
		{"metadata_api_key_over_access_token", slots{meta: map[string]any{"api_key": "k-md", "access_token": "k-md-at"}, storage: store("k-st", "", "")}, "k-md"},
		{"metadata_api_key_dca_skipped", slots{meta: map[string]any{"api_key": "dca:x", "access_token": "k-md-at"}}, "k-md-at"},
		{"metadata_access_token_over_storage", slots{meta: map[string]any{"access_token": "k-md-at"}, storage: store("k-st", "k-st-at", "")}, "k-md-at"},
		{"storage_api_key_over_access_token", slots{meta: map[string]any{"type": "meta"}, storage: store("k-st", "k-st-at", "")}, "k-st"},
		{"storage_access_token", slots{meta: map[string]any{"type": "meta"}, storage: store("", "k-st-at", "")}, "k-st-at"},
		{"storage_access_token_dca_skipped", slots{meta: map[string]any{"type": "meta"}, storage: store("", "dca:z", "dca:z")}, ""},
		{"nothing", slots{meta: map[string]any{"type": "meta"}}, ""},
	}
	for _, tc := range keyCases {
		t.Run("key/"+tc.name, func(t *testing.T) {
			if got := metaADKey(build(tc.in)); got != tc.want {
				t.Fatalf("metaADKey = %q, want %q", got, tc.want)
			}
		})
	}
	dcaCases := []struct {
		name string
		in   slots
		want string
	}{
		{"attr_dca_token_first", slots{attrs: map[string]string{"dca_token": "d-attr", "access_token": "dca:at"}, meta: map[string]any{"dca_token": "d-md"}, storage: store("", "", "d-st")}, "d-attr"},
		{"attr_access_token_dca_over_metadata", slots{attrs: map[string]string{"access_token": "dca:at"}, meta: map[string]any{"dca_token": "d-md"}}, "dca:at"},
		{"attr_access_token_not_dca_ignored", slots{attrs: map[string]string{"access_token": "plain"}, meta: map[string]any{"dca_token": "d-md"}}, "d-md"},
		{"metadata_dca_token_over_access_token", slots{meta: map[string]any{"dca_token": "d-md", "access_token": "dca:md-at"}, storage: store("", "", "d-st")}, "d-md"},
		{"metadata_access_token_dca_over_storage", slots{meta: map[string]any{"access_token": "dca:md-at"}, storage: store("", "", "d-st")}, "dca:md-at"},
		{"storage_dca_token_over_access_token", slots{meta: map[string]any{"type": "meta"}, storage: store("", "dca:st-at", "d-st")}, "d-st"},
		{"storage_access_token_dca", slots{meta: map[string]any{"type": "meta"}, storage: store("", "dca:st-at", "")}, "dca:st-at"},
		{"storage_access_token_not_dca", slots{meta: map[string]any{"type": "meta"}, storage: store("k", "plain", "")}, ""},
		{"nothing", slots{meta: map[string]any{"type": "meta"}}, ""},
	}
	for _, tc := range dcaCases {
		t.Run("dca/"+tc.name, func(t *testing.T) {
			if got := metaADDCAToken(build(tc.in)); got != tc.want {
				t.Fatalf("metaADDCAToken = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("storage_only_fingerprint", func(t *testing.T) {
		mk := func(api, dca string) *Auth {
			return &Auth{ID: "n2", Provider: "meta", Metadata: map[string]any{"type": "meta"}, Storage: store(api, "", dca)}
		}
		base := mk("k-1", "dca:1")
		if metaADKey(base) != "k-1" || metaADDCAToken(base) != "dca:1" {
			t.Fatalf("storage-only credential: key=%q dca=%q", metaADKey(base), metaADDCAToken(base))
		}
		fp := metaADFingerprint(base)
		if metaADFingerprint(mk("k-2", "dca:1")) == fp {
			t.Fatalf("fingerprint did not change with the Storage key")
		}
		if metaADFingerprint(mk("k-1", "dca:2")) == fp {
			t.Fatalf("fingerprint did not change with the Storage dca_token")
		}
		noisy := mk("k-1", "dca:1")
		noisy.Attributes = map[string]string{"base_url": "https://other.example.invalid"}
		noisy.Metadata["last_refresh"] = "2026-01-01T00:00:00Z"
		if metaADFingerprint(noisy) != fp {
			t.Fatalf("fingerprint changed with unrelated slots (Attributes base_url, Metadata last_refresh)")
		}
	})

	t.Run("storage_only_is_not_no_dca_token", func(t *testing.T) {
		m := newMetaADFxManager(t, true, nil, newMetaADFxExecutor(),
			&Auth{ID: metaADFxPrimaryID, Provider: "meta", Metadata: map[string]any{"type": "meta"}, Storage: store("k-1", "", "dca:1")})
		target := metaADFxGet(t, m, metaADFxPrimaryID)
		if m.metaAutoDisableOnUnauthorized(target, "") {
			t.Fatalf("metaAutoDisableOnUnauthorized = true for a Storage-only credential that has a dca_token")
		}
		metaADFxRequireNotTracked(t, metaADFxGet(t, m, metaADFxPrimaryID))
		if !m.metaAutoDisableCanMint(target) {
			t.Fatalf("metaAutoDisableCanMint = false for a Storage-only credential that has a dca_token")
		}
	})

	t.Run("no_dca_anywhere_is_no_dca_token", func(t *testing.T) {
		m := newMetaADFxManager(t, true, nil, newMetaADFxExecutor(),
			&Auth{ID: metaADFxPrimaryID, Provider: "meta", Metadata: map[string]any{"type": "meta"}, Storage: store("k-1", "", "")})
		target := metaADFxGet(t, m, metaADFxPrimaryID)
		if !m.metaAutoDisableOnUnauthorized(target, "") {
			t.Fatalf("metaAutoDisableOnUnauthorized = false, want true without any dca_token")
		}
		metaADFxRequireTracked(t, metaADFxGet(t, m, metaADFxPrimaryID), metaADStatePending, metaADReasonNoDCAToken)
	})
}

// F5 (refresh error): the background confirmation passes no failed token, so the gate
// taken inside metaAutoDisableOnRefreshError is the only protection of its transition.
func TestMetaAutoDisableFixup_RefreshErrorTransitionSurvivesConcurrentSave(t *testing.T) {
	cases := []struct {
		name   string
		status int
		check  func(t *testing.T, got *Auth, raw metaAutoDisableState, before, after time.Time)
	}{
		{
			name:   "confirmation_401_confirms",
			status: http.StatusUnauthorized,
			check: func(t *testing.T, got *Auth, raw metaAutoDisableState, before, _ time.Time) {
				if !raw.confirmed {
					t.Fatalf("confirmed = false, want the 401 confirmation to survive the concurrent save")
				}
				if got.NextRefreshAfter.Before(before.Add(23 * time.Hour)) {
					t.Fatalf("NextRefreshAfter = %v, want >= now+23h", got.NextRefreshAfter)
				}
			},
		},
		{
			name:   "confirmation_500_retries",
			status: http.StatusInternalServerError,
			check: func(t *testing.T, got *Auth, raw metaAutoDisableState, before, after time.Time) {
				if raw.state != metaADStateRetry || raw.attempts != 1 {
					t.Fatalf("raw state = %q attempts = %d, want retry and 1", raw.state, raw.attempts)
				}
				d := metaADRetryDelay(1)
				if got.NextRefreshAfter.Before(before.Add(d-time.Second)) || got.NextRefreshAfter.After(after.Add(d+time.Second)) {
					t.Fatalf("NextRefreshAfter = %v, want about now+%v", got.NextRefreshAfter, d)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newMetaADFxStore()
			m, exec := metaADFxEnterPendingViaRequest(t, store, http.StatusUnauthorized)
			exec.enqueue(metaADFxMintErr(tc.status))
			metaADFxMakeDue(m, metaADFxPrimaryID)

			store.armBlock()
			unrelated := metaADFxPrimary()
			unrelated.Attributes = map[string]string{"label": "unrelated change"}
			doneA := make(chan error, 1)
			go func() {
				_, err := m.Update(context.Background(), unrelated)
				doneA <- err
			}()
			<-store.saving

			before := time.Now()
			doneB := make(chan struct{})
			go func() {
				defer close(doneB)
				m.refreshAuth(context.Background(), metaADFxPrimaryID)
			}()
			state := m.metadataPersistPreempt(metaADFxPrimaryID)
		wait:
			for {
				state.mu.Lock()
				waiters := state.waiters
				state.mu.Unlock()
				if waiters >= 1 {
					break wait
				}
				select {
				case <-doneB:
					break wait
				default:
					runtime.Gosched()
				}
			}
			close(store.release)
			if err := <-doneA; err != nil {
				t.Fatalf("Update: %v", err)
			}
			<-doneB
			after := time.Now()

			if got := exec.refreshCount(); got != 2 {
				t.Fatalf("Refresh calls = %d, want 2 (request mint + confirmation)", got)
			}
			got := metaADFxGet(t, m, metaADFxPrimaryID)
			metaADFxRequireTracked(t, got, map[bool]string{true: metaADStatePending, false: metaADStateRetry}[tc.status == http.StatusUnauthorized], metaADReasonMintRejected)
			if got.Attributes["label"] != "unrelated change" {
				t.Fatalf("the concurrent save was lost: attributes = %v", got.Attributes)
			}
			tc.check(t, got, metaADFxRaw(m, metaADFxPrimaryID), before, after)
		})
	}
}
