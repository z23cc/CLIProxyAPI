package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	metaauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/meta"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

const (
	metaADPrimaryID = "aa-meta-primary"
	metaADBackupID  = "bb-meta-backup"
	metaADModelA    = "meta-model-a"
	metaADModelB    = "meta-model-b"
	metaADModelC    = "meta-model-c"
)

// metaADRefreshResult is one queued outcome for metaADTestExecutor.Refresh.
// A nil err mints a new key; a non-nil err is returned as the mint failure.
type metaADRefreshResult struct {
	err error
	// mintInvalid makes the minted key rejected by upstream as well.
	mintInvalid bool
	// sameKey makes the mint succeed but hand back the credential unchanged.
	sameKey bool
}

// metaADTestExecutor is a programmable Meta executor. Tokens in invalid get a 401
// from Execute/ExecuteStream. Refresh pops its outcome from queue (default: mint a
// live key) and, like the real executor, is a successful no-op without a dca_token.
type metaADTestExecutor struct {
	mu           sync.Mutex
	invalid      map[string]struct{}
	queue        []metaADRefreshResult
	refreshCalls int
	mintSeq      int
	calls        []string

	// streamChunkErr reports a rejected key as an error chunk of the stream (the bootstrap
	// path) instead of an error returned by ExecuteStream.
	streamChunkErr bool
	// refreshEntered, when non-nil, gets a (non-blocking) send each time Refresh starts, and
	// refreshRelease, when non-nil, blocks every Refresh until it is closed or sent to.
	refreshEntered chan struct{}
	refreshRelease chan struct{}
}

func newMetaADTestExecutor(invalidTokens ...string) *metaADTestExecutor {
	e := &metaADTestExecutor{invalid: make(map[string]struct{})}
	for _, token := range invalidTokens {
		e.invalid[token] = struct{}{}
	}
	return e
}

func (e *metaADTestExecutor) Identifier() string { return "meta" }

func (e *metaADTestExecutor) enqueue(results ...metaADRefreshResult) {
	e.mu.Lock()
	e.queue = append(e.queue, results...)
	e.mu.Unlock()
}

// mintErr wraps a MintError the way the real executor reports a failed mint.
func metaADMintErr(status int) error {
	return fmt.Errorf("meta executor: mint API key failed: %w", &metaauth.MintError{Status: status, Body: "x"})
}

func metaADNetworkErr() error {
	return fmt.Errorf("meta executor: mint API key failed: %w", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")})
}

func (e *metaADTestExecutor) run(auth *Auth) ([]byte, error) {
	e.mu.Lock()
	e.calls = append(e.calls, auth.ID)
	token := authAccessToken(auth)
	_, invalid := e.invalid[token]
	e.mu.Unlock()
	if invalid {
		return nil, &Error{HTTPStatus: http.StatusUnauthorized, Message: "key rejected"}
	}
	return []byte(auth.ID + ":" + token), nil
}

func (e *metaADTestExecutor) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	payload, err := e.run(auth)
	return cliproxyexecutor.Response{Payload: payload}, err
}

func (e *metaADTestExecutor) ExecuteStream(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	payload, err := e.run(auth)
	if err != nil {
		if e.streamChunkErr {
			ch := make(chan cliproxyexecutor.StreamChunk, 1)
			ch <- cliproxyexecutor.StreamChunk{Err: err}
			close(ch)
			return &cliproxyexecutor.StreamResult{Chunks: ch}, nil
		}
		return nil, err
	}
	ch := make(chan cliproxyexecutor.StreamChunk, 1)
	ch <- cliproxyexecutor.StreamChunk{Payload: payload}
	close(ch)
	return &cliproxyexecutor.StreamResult{Chunks: ch}, nil
}

func (e *metaADTestExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	e.mu.Lock()
	e.refreshCalls++
	var res metaADRefreshResult
	if len(e.queue) > 0 {
		res = e.queue[0]
		e.queue = e.queue[1:]
	}
	if res.err == nil && !res.sameKey && metaADDCAToken(auth) != "" {
		e.mintSeq++
	}
	seq := e.mintSeq
	entered, release := e.refreshEntered, e.refreshRelease
	e.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		<-release
	}
	if res.err != nil {
		return nil, res.err
	}
	dca := metaADDCAToken(auth)
	if dca == "" {
		// The real executor returns the auth unchanged when there is nothing to mint with.
		return auth, nil
	}
	key := fmt.Sprintf("minted-key-%d", seq)
	if res.sameKey {
		key = authOuterAccessToken(auth)
	}
	if res.mintInvalid {
		e.mu.Lock()
		e.invalid[key] = struct{}{}
		e.mu.Unlock()
	}
	// Write every slot the real MetaExecutor.Refresh writes on a successful mint, even
	// when the key is unchanged, starting from whatever the auth already holds.
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

func (e *metaADTestExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, &Error{HTTPStatus: http.StatusNotImplemented, Message: "not implemented"}
}

func (e *metaADTestExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func (e *metaADTestExecutor) RefreshCalls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.refreshCalls
}

func (e *metaADTestExecutor) Calls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.calls...)
}

func (e *metaADTestExecutor) CallsFor(id string) int {
	n := 0
	for _, c := range e.Calls() {
		if c == id {
			n++
		}
	}
	return n
}

// metaADPreparerExecutor adds RequestAuthPreparer for DCA-only credentials: with no
// key and a dca_token present it mints in PrepareRequestAuth, using the same queue.
type metaADPreparerExecutor struct {
	*metaADTestExecutor
	prepareCalls int
}

func (e *metaADPreparerExecutor) ShouldPrepareRequestAuth(auth *Auth) bool {
	return authAccessToken(auth) == "" && metaADDCAToken(auth) != ""
}

func (e *metaADPreparerExecutor) PrepareRequestAuth(ctx context.Context, auth *Auth) (*Auth, error) {
	e.mu.Lock()
	e.prepareCalls++
	e.mu.Unlock()
	return e.Refresh(ctx, auth)
}

func metaADSwitch(enabled bool) *internalconfig.Config {
	return &internalconfig.Config{Routing: internalconfig.RoutingConfig{MetaAutoDisable: internalconfig.MetaAutoDisableConfig{Enabled: enabled}}}
}

func metaADPrimary() *Auth {
	return &Auth{
		ID:       metaADPrimaryID,
		Provider: "meta",
		Metadata: map[string]any{"access_token": "dead-key-0", "api_key": "dead-key-0", "dca_token": "dca:primary"},
	}
}

func metaADBackup() *Auth {
	return &Auth{
		ID:       metaADBackupID,
		Provider: "meta",
		Metadata: map[string]any{"access_token": "good-key", "api_key": "good-key", "dca_token": "dca:backup"},
	}
}

// newMetaADManager builds a manager with the executor, registers the auths for the
// three test models, and sets the auto-disable switch.
func newMetaADManager(t *testing.T, enabled bool, exec ProviderExecutor, auths ...*Auth) *Manager {
	t.Helper()
	m := NewManager(nil, nil, nil)
	m.RegisterExecutor(exec)
	m.SetConfig(metaADSwitch(enabled))
	reg := registry.GetGlobalRegistry()
	models := []*registry.ModelInfo{{ID: metaADModelA}, {ID: metaADModelB}, {ID: metaADModelC}}
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

func metaADExecute(m *Manager, model string) (cliproxyexecutor.Response, error) {
	return m.Execute(context.Background(), []string{"meta"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
}

func metaADGet(t *testing.T, m *Manager, id string) *Auth {
	t.Helper()
	a, ok := m.GetByID(id)
	if !ok || a == nil {
		t.Fatalf("auth %s missing", id)
	}
	return a
}

// metaADMakeDue backdates the live auth's NextRefreshAfter so a confirmation is due.
func metaADMakeDue(m *Manager, id string) {
	m.mu.Lock()
	m.auths[id].NextRefreshAfter = time.Now().Add(-time.Second)
	m.mu.Unlock()
}

// metaADConfirmDue makes the confirmation due and runs it through the background entry.
func metaADConfirmDue(m *Manager, id string) {
	metaADMakeDue(m, id)
	m.refreshAuth(context.Background(), id)
}

// metaADRawState reads the raw in-memory state of the live auth under the manager lock.
func metaADRawState(m *Manager, id string) metaAutoDisableState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.auths[id].metaAD
}

func metaADRequireTracked(t *testing.T, a *Auth, wantState, wantReason string) {
	t.Helper()
	state, reason, since, ok := a.MetaAutoDisableStatus()
	if !ok || state != wantState || reason != wantReason || since.IsZero() {
		t.Fatalf("MetaAutoDisableStatus = (%q, %q, %v, %v), want (%q, %q, non-zero, true)", state, reason, since, ok, wantState, wantReason)
	}
}

func metaADRequireNotTracked(t *testing.T, a *Auth) {
	t.Helper()
	if state, reason, _, ok := a.MetaAutoDisableStatus(); ok {
		t.Fatalf("auth is tracked (%q, %q), want not tracked", state, reason)
	}
}

// metaADRequireBlockedShape checks the shape shared by every tracked state.
func metaADRequireBlockedShape(t *testing.T, a *Auth, wantMessageReason string) {
	t.Helper()
	if !a.Unavailable || a.Status != StatusError {
		t.Fatalf("Unavailable=%v Status=%v, want unavailable error", a.Unavailable, a.Status)
	}
	if a.Disabled || a.Status == StatusDisabled {
		t.Fatalf("auth must not be disabled by this feature")
	}
	if a.NextRefreshAfter.IsZero() {
		t.Fatalf("NextRefreshAfter is zero, must stay non-zero while tracked")
	}
	if hasUnauthorizedAuthFailure(a) {
		t.Fatalf("hasUnauthorizedAuthFailure = true, want false while tracked")
	}
	// After a request-path failover MarkResult overwrites StatusMessage and LastError with
	// the 401 result, so callers pass an empty reason to skip the message check there.
	if wantMessageReason == "" {
		return
	}
	if want := fmt.Sprintf("meta auto-disable pending (%s)", wantMessageReason); a.StatusMessage != want {
		t.Fatalf("StatusMessage = %q, want %q", a.StatusMessage, want)
	}
}

func metaADRequireDueIn(t *testing.T, a *Auth, before, after time.Time, d time.Duration) {
	t.Helper()
	if a.NextRefreshAfter.Before(before.Add(d-time.Second)) || a.NextRefreshAfter.After(after.Add(d+time.Second)) {
		t.Fatalf("NextRefreshAfter = %v, want about now+%v (window %v..%v)", a.NextRefreshAfter, d, before.Add(d), after.Add(d))
	}
}

func metaADRequireBlockedEverywhere(t *testing.T, a *Auth) {
	t.Helper()
	now := time.Now()
	for _, model := range []string{metaADModelA, metaADModelB, metaADModelC, ""} {
		if blocked, _, _ := isAuthBlockedForModel(a, model, now); !blocked {
			t.Fatalf("auth not blocked for model %q", model)
		}
	}
}

// metaADEnterPendingViaRequest drives the real request path: the primary's key is
// rejected, the mint is rejected too, the request fails over to the backup.
func metaADEnterPendingViaRequest(t *testing.T, mintStatus int) (*Manager, *metaADTestExecutor) {
	t.Helper()
	exec := newMetaADTestExecutor("dead-key-0")
	exec.enqueue(metaADRefreshResult{err: metaADMintErr(mintStatus)})
	m := newMetaADManager(t, true, exec, metaADPrimary(), metaADBackup())
	resp, err := metaADExecute(m, metaADModelA)
	if err != nil {
		t.Fatalf("Execute error = %v, want success via backup", err)
	}
	if got := string(resp.Payload); got != metaADBackupID+":good-key" {
		t.Fatalf("payload = %q, want backup response", got)
	}
	return m, exec
}

func TestMetaAutoDisable_MintRejectedEntersPendingViaRequest(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(fmt.Sprintf("mint_%d", status), func(t *testing.T) {
			before := time.Now()
			m, exec := metaADEnterPendingViaRequest(t, status)
			after := time.Now()

			if got := exec.RefreshCalls(); got != 1 {
				t.Fatalf("Refresh calls = %d, want 1", got)
			}
			if got := exec.CallsFor(metaADPrimaryID); got != 1 {
				t.Fatalf("primary upstream calls = %d, want 1 (no retry after a failed mint)", got)
			}
			primary := metaADGet(t, m, metaADPrimaryID)
			metaADRequireTracked(t, primary, metaADStatePending, metaADReasonMintRejected)
			// MarkResult of the failed-over 401 runs after the pending state was entered and
			// replaces StatusMessage/LastError and re-sets a ~30m auth NextRetryAfter.
			metaADRequireBlockedShape(t, primary, "")
			metaADRequireDueIn(t, primary, before, after, metaADConfirmDelay)
			metaADRequireBlockedEverywhere(t, primary)
		})
	}
}

func TestMetaAutoDisable_TransientMintFailureIsNotTracked(t *testing.T) {
	cases := map[string]error{
		"mint_500": metaADMintErr(http.StatusInternalServerError),
		"network":  metaADNetworkErr(),
	}
	for name, mintErr := range cases {
		t.Run(name, func(t *testing.T) {
			exec := newMetaADTestExecutor("dead-key-0")
			exec.enqueue(metaADRefreshResult{err: mintErr})
			m := newMetaADManager(t, true, exec, metaADPrimary(), metaADBackup())
			if _, err := metaADExecute(m, metaADModelA); err != nil {
				t.Fatalf("Execute error = %v, want success via backup", err)
			}
			if got := exec.RefreshCalls(); got != 1 {
				t.Fatalf("Refresh calls = %d, want 1", got)
			}
			metaADRequireNotTracked(t, metaADGet(t, m, metaADPrimaryID))
		})
	}
}

// metaADSeedQuotaModelState adds an unrelated quota-style model state to the primary.
func metaADSeedQuotaModelState(m *Manager, id, model string) time.Time {
	recoverAt := time.Now().Add(10 * time.Minute)
	m.mu.Lock()
	live := m.auths[id]
	if live.ModelStates == nil {
		live.ModelStates = make(map[string]*ModelState)
	}
	live.ModelStates[model] = &ModelState{
		Status:         StatusError,
		StatusMessage:  "quota exceeded",
		Unavailable:    true,
		NextRetryAfter: recoverAt,
		LastError:      &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota exceeded"},
		Quota:          QuotaState{Exceeded: true, Reason: "quota exceeded", NextRecoverAt: recoverAt},
	}
	m.mu.Unlock()
	return recoverAt
}

func TestMetaAutoDisable_ConfirmationMintSuccessRestores(t *testing.T) {
	m, exec := metaADEnterPendingViaRequest(t, http.StatusUnauthorized)
	pending := metaADGet(t, m, metaADPrimaryID)
	// The failover MarkResult left the 401 leftovers the restore must clear.
	if pending.NextRetryAfter.IsZero() || pending.ModelStates[metaADModelA] == nil || !pending.ModelStates[metaADModelA].Unavailable {
		t.Fatalf("precondition: want auth NextRetryAfter and a model-a state left by MarkResult, got retry=%v states=%v", pending.NextRetryAfter, pending.ModelStates)
	}
	recoverAt := metaADSeedQuotaModelState(m, metaADPrimaryID, metaADModelC)

	metaADConfirmDue(m, metaADPrimaryID)

	if got := exec.RefreshCalls(); got != 2 {
		t.Fatalf("Refresh calls = %d, want 2 (request mint + one confirmation mint)", got)
	}
	got := metaADGet(t, m, metaADPrimaryID)
	metaADRequireNotTracked(t, got)
	if got.Unavailable || got.Status != StatusActive {
		t.Fatalf("Unavailable=%v Status=%v, want available active", got.Unavailable, got.Status)
	}
	if !got.NextRefreshAfter.IsZero() || !got.NextRetryAfter.IsZero() {
		t.Fatalf("NextRefreshAfter=%v NextRetryAfter=%v, want both zero", got.NextRefreshAfter, got.NextRetryAfter)
	}
	if got.StatusMessage != "" || got.LastError != nil {
		t.Fatalf("StatusMessage=%q LastError=%v, want cleared", got.StatusMessage, got.LastError)
	}
	if key := authAccessToken(got); key != "minted-key-1" {
		t.Fatalf("access token = %q, want the key minted by the confirmation", key)
	}
	if raw := metaADRawState(m, metaADPrimaryID); raw.state != "" || raw.reason != "" || raw.confirmed {
		t.Fatalf("raw metaAD = %+v, want cleared", raw)
	} else if raw.replacedKey != "" || !raw.replacedAt.IsZero() {
		t.Fatalf("raw metaAD = %+v, a confirmation mint must not stamp the replaced-key window", raw)
	}
	// The 401 model state is cleared, the unrelated quota state is untouched.
	if st := got.ModelStates[metaADModelA]; st != nil && (st.Unavailable || st.LastError != nil || !st.NextRetryAfter.IsZero()) {
		t.Fatalf("model-a 401 state not cleared: %+v", st)
	}
	stC := got.ModelStates[metaADModelC]
	if stC == nil || !stC.Unavailable || !stC.NextRetryAfter.Equal(recoverAt) || !stC.Quota.Exceeded || stC.LastError == nil || stC.LastError.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("unrelated model-c state was touched: %+v", stC)
	}
	if blocked, _, _ := isAuthBlockedForModel(got, metaADModelA, time.Now()); blocked {
		t.Fatalf("restored auth still blocked for model a")
	}
	// A following request can use the primary again (round robin reaches it).
	before := exec.CallsFor(metaADPrimaryID)
	for i := 0; i < 2; i++ {
		if _, err := metaADExecute(m, metaADModelA); err != nil {
			t.Fatalf("Execute after restore: %v", err)
		}
	}
	if exec.CallsFor(metaADPrimaryID) <= before {
		t.Fatalf("primary was not selected after restore; calls = %v", exec.Calls())
	}
}

func TestMetaAutoDisable_ConfirmationMintRejectedParksConfirmed(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(fmt.Sprintf("mint_%d", status), func(t *testing.T) {
			m, exec := metaADEnterPendingViaRequest(t, http.StatusUnauthorized)
			exec.enqueue(metaADRefreshResult{err: metaADMintErr(status)})

			before := time.Now()
			metaADConfirmDue(m, metaADPrimaryID)
			after := time.Now()

			if got := exec.RefreshCalls(); got != 2 {
				t.Fatalf("Refresh calls = %d, want 2", got)
			}
			got := metaADGet(t, m, metaADPrimaryID)
			metaADRequireTracked(t, got, metaADStatePending, metaADReasonMintRejected)
			if !got.metaAD.confirmed {
				t.Fatalf("metaAD.confirmed = false, want true")
			}
			metaADRequireBlockedShape(t, got, metaADReasonMintRejected)
			metaADRequireBlockedEverywhere(t, got)
			if got.NextRefreshAfter.Before(before.Add(23 * time.Hour)) {
				t.Fatalf("NextRefreshAfter = %v, want >= now+23h", got.NextRefreshAfter)
			}
			metaADRequireDueIn(t, got, before, after, metaADConfirmedHold)
			if !got.NextRetryAfter.IsZero() {
				t.Fatalf("NextRetryAfter = %v, want zero", got.NextRetryAfter)
			}

			// A confirmed credential is never minted again, even when due.
			metaADConfirmDue(m, metaADPrimaryID)
			if calls := exec.RefreshCalls(); calls != 2 {
				t.Fatalf("Refresh calls after second due = %d, want 2 (confirmed is parked)", calls)
			}
			metaADMakeDue(m, metaADPrimaryID)
			due := metaADGet(t, m, metaADPrimaryID)
			if m.shouldRefresh(due, time.Now()) {
				t.Fatalf("shouldRefresh = true for a confirmed credential")
			}
			metaADRequireTracked(t, due, metaADStatePending, metaADReasonMintRejected)
		})
	}
}

func TestMetaAutoDisable_ConfirmationTransientFailureRetriesWithBackoff(t *testing.T) {
	cases := map[string]error{
		"network":  metaADNetworkErr(),
		"mint_500": metaADMintErr(http.StatusInternalServerError),
	}
	for name, transient := range cases {
		t.Run(name, func(t *testing.T) {
			m, exec := metaADEnterPendingViaRequest(t, http.StatusForbidden)
			wantDelays := []time.Duration{5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, time.Hour}
			for i, want := range wantDelays {
				exec.enqueue(metaADRefreshResult{err: transient})
				before := time.Now()
				metaADConfirmDue(m, metaADPrimaryID)
				after := time.Now()

				if got := exec.RefreshCalls(); got != 2+i {
					t.Fatalf("attempt %d: Refresh calls = %d, want %d", i+1, got, 2+i)
				}
				got := metaADGet(t, m, metaADPrimaryID)
				metaADRequireTracked(t, got, metaADStateRetry, metaADReasonMintRejected)
				if got.metaAD.confirmed {
					t.Fatalf("attempt %d: a transient failure must never confirm", i+1)
				}
				metaADRequireBlockedShape(t, got, metaADReasonMintRejected)
				metaADRequireBlockedEverywhere(t, got)
				metaADRequireDueIn(t, got, before, after, want)
			}
			// The credential recovers once the mint works again.
			metaADConfirmDue(m, metaADPrimaryID)
			got := metaADGet(t, m, metaADPrimaryID)
			metaADRequireNotTracked(t, got)
			if got.Unavailable || got.Status != StatusActive || !got.NextRefreshAfter.IsZero() {
				t.Fatalf("not restored: unavailable=%v status=%v nextRefresh=%v", got.Unavailable, got.Status, got.NextRefreshAfter)
			}
		})
	}
}

func TestMetaAutoDisable_NoDCATokenNeverMints(t *testing.T) {
	exec := newMetaADTestExecutor("dead-key-0")
	primary := &Auth{
		ID:       metaADPrimaryID,
		Provider: "meta",
		Metadata: map[string]any{"access_token": "dead-key-0", "api_key": "dead-key-0"},
	}
	m := newMetaADManager(t, true, exec, primary, metaADBackup())

	if _, err := metaADExecute(m, metaADModelA); err != nil {
		t.Fatalf("Execute error = %v, want success via backup", err)
	}
	if got := exec.RefreshCalls(); got != 0 {
		t.Fatalf("Refresh calls = %d, want 0 (nothing to mint with)", got)
	}
	got := metaADGet(t, m, metaADPrimaryID)
	metaADRequireTracked(t, got, metaADStatePending, metaADReasonNoDCAToken)
	metaADRequireBlockedShape(t, got, "")
	metaADRequireBlockedEverywhere(t, got)

	// The executor's Refresh would be a successful no-op here and read as a recovery.
	metaADConfirmDue(m, metaADPrimaryID)
	if got := exec.RefreshCalls(); got != 0 {
		t.Fatalf("Refresh calls after confirmation = %d, want 0", got)
	}
	got = metaADGet(t, m, metaADPrimaryID)
	metaADRequireTracked(t, got, metaADStatePending, metaADReasonNoDCAToken)
	if !got.metaAD.confirmed {
		t.Fatalf("metaAD.confirmed = false, want true (no_dca_token goes straight to confirmed)")
	}
	metaADRequireBlockedShape(t, got, metaADReasonNoDCAToken)
	metaADRequireBlockedEverywhere(t, got)
}

// metaADExecuteStream runs one streaming request and drains the returned stream.
func metaADExecuteStream(m *Manager, model string) (string, error) {
	stream, err := m.ExecuteStream(context.Background(), []string{"meta"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if err != nil {
		return "", err
	}
	var payload []byte
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			return "", chunk.Err
		}
		payload = append(payload, chunk.Payload...)
	}
	return string(payload), nil
}

func TestMetaAutoDisable_NewKeyRejectedEntersPendingInSameRequest(t *testing.T) {
	paths := []struct {
		name string
		run  func(t *testing.T, m *Manager, exec *metaADTestExecutor)
	}{
		{"Execute", func(t *testing.T, m *Manager, _ *metaADTestExecutor) {
			resp, err := metaADExecute(m, metaADModelA)
			if err != nil {
				t.Fatalf("Execute error = %v, want success via backup", err)
			}
			if got := string(resp.Payload); got != metaADBackupID+":good-key" {
				t.Fatalf("payload = %q, want backup response", got)
			}
		}},
		{"ExecuteStream error", func(t *testing.T, m *Manager, _ *metaADTestExecutor) {
			got, err := metaADExecuteStream(m, metaADModelA)
			if err != nil || got != metaADBackupID+":good-key" {
				t.Fatalf("ExecuteStream = (%q, %v), want backup payload", got, err)
			}
		}},
		{"ExecuteStream bootstrap", func(t *testing.T, m *Manager, exec *metaADTestExecutor) {
			exec.streamChunkErr = true
			got, err := metaADExecuteStream(m, metaADModelA)
			if err != nil || got != metaADBackupID+":good-key" {
				t.Fatalf("ExecuteStream = (%q, %v), want backup payload", got, err)
			}
		}},
	}
	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			exec := newMetaADTestExecutor("dead-key-0")
			exec.enqueue(metaADRefreshResult{mintInvalid: true})
			m := newMetaADManager(t, true, exec, metaADPrimary(), metaADBackup())

			before := time.Now()
			path.run(t, m, exec)
			after := time.Now()

			if got := exec.RefreshCalls(); got != 1 {
				t.Fatalf("Refresh calls = %d, want exactly 1", got)
			}
			if got := exec.CallsFor(metaADPrimaryID); got != 2 {
				t.Fatalf("primary upstream calls = %d, want 2 (old key, then minted key)", got)
			}
			got := metaADGet(t, m, metaADPrimaryID)
			metaADRequireTracked(t, got, metaADStatePending, metaADReasonNewKeyRejected)
			metaADRequireDueIn(t, got, before, after, metaADConfirmDelay)
			if got.metaAD.replacedKey == "" {
				t.Fatalf("replacedKey is empty, want the minted key's fingerprint")
			}
			if hasUnauthorizedAuthFailure(got) {
				t.Fatalf("hasUnauthorizedAuthFailure = true, want false")
			}
			metaADRequireBlockedEverywhere(t, got)

			// The tracked auth is scheduled and refreshed when due, not stuck in a silent block.
			at := time.Now().Add(metaADConfirmDelay + time.Minute)
			if next, schedule := nextRefreshCheckAt(at, got, time.Second); !schedule || !next.Equal(at) {
				t.Fatalf("nextRefreshCheckAt = (%v, %v), want (%v, true)", next, schedule, at)
			}
			if !m.shouldRefresh(got, at) {
				t.Fatalf("shouldRefresh = false once the confirmation is due")
			}

			// Confirmation never mints for new_key_rejected and ends confirmed.
			metaADConfirmDue(m, metaADPrimaryID)
			if got := exec.RefreshCalls(); got != 1 {
				t.Fatalf("Refresh calls after confirmation = %d, want 1", got)
			}
			got = metaADGet(t, m, metaADPrimaryID)
			metaADRequireTracked(t, got, metaADStatePending, metaADReasonNewKeyRejected)
			if !got.metaAD.confirmed {
				t.Fatalf("metaAD.confirmed = false, want true")
			}
			metaADRequireBlockedShape(t, got, metaADReasonNewKeyRejected)
		})
	}
}

func TestMetaAutoDisable_NewKeyRejectedSwitchOffControl(t *testing.T) {
	exec := newMetaADTestExecutor("dead-key-0")
	exec.enqueue(metaADRefreshResult{mintInvalid: true})
	m := newMetaADManager(t, false, exec, metaADPrimary(), metaADBackup())
	if _, err := metaADExecute(m, metaADModelA); err != nil {
		t.Fatalf("Execute error = %v, want success via backup", err)
	}
	if exec.RefreshCalls() != 1 || exec.CallsFor(metaADPrimaryID) != 2 {
		t.Fatalf("Refresh calls = %d, primary calls = %d, want 1 and 2", exec.RefreshCalls(), exec.CallsFor(metaADPrimaryID))
	}
	if raw := metaADRawState(m, metaADPrimaryID); raw != (metaAutoDisableState{}) {
		t.Fatalf("raw metaAD = %+v, want empty with the switch off", raw)
	}
	got := metaADGet(t, m, metaADPrimaryID)
	metaADRequireNotTracked(t, got)
	// Pre-existing behaviour: the failed retry is a plain 401 cooldown.
	if !got.Unavailable || got.NextRetryAfter.IsZero() {
		t.Fatalf("unavailable=%v nextRetry=%v, want the legacy 401 cooldown", got.Unavailable, got.NextRetryAfter)
	}
}

func TestMetaAutoDisable_NewKeyRejectedOnSecondRequestSkipsMint(t *testing.T) {
	exec := newMetaADTestExecutor("dead-key-0")
	m := newMetaADManager(t, true, exec, metaADPrimary(), metaADBackup())
	// The live key was minted to replace a rejected key a moment ago.
	m.mu.Lock()
	m.auths[metaADPrimaryID].metaAD.replacedKey = metaADTokenFingerprint("dead-key-0")
	m.auths[metaADPrimaryID].metaAD.replacedAt = time.Now()
	m.mu.Unlock()

	before := time.Now()
	resp, err := metaADExecute(m, metaADModelA)
	after := time.Now()
	if err != nil {
		t.Fatalf("Execute error = %v, want success via backup", err)
	}
	if got := string(resp.Payload); got != metaADBackupID+":good-key" {
		t.Fatalf("payload = %q, want backup response", got)
	}
	if got := exec.RefreshCalls(); got != 0 {
		t.Fatalf("Refresh calls = %d, want 0 (no second mint)", got)
	}
	if got := exec.CallsFor(metaADPrimaryID); got != 1 {
		t.Fatalf("primary upstream calls = %d, want 1", got)
	}
	got := metaADGet(t, m, metaADPrimaryID)
	metaADRequireTracked(t, got, metaADStatePending, metaADReasonNewKeyRejected)
	metaADRequireDueIn(t, got, before, after, metaADConfirmDelay)
	metaADRequireBlockedEverywhere(t, got)
}

func TestMetaAutoDisable_RejectionOutsideReplacedKeyWindowMintsNormally(t *testing.T) {
	exec := newMetaADTestExecutor("dead-key-0")
	m := newMetaADManager(t, true, exec, metaADPrimary(), metaADBackup())

	// First rejection: the key is replaced with a live one (stamps the replaced-key window).
	if _, err := m.refreshAuthForRequest(context.Background(), metaADPrimaryID, "dead-key-0"); err != nil {
		t.Fatalf("initial re-mint: %v", err)
	}
	minted := authAccessToken(metaADGet(t, m, metaADPrimaryID))
	if minted != "minted-key-1" {
		t.Fatalf("minted key = %q, want minted-key-1", minted)
	}
	if metaADGet(t, m, metaADPrimaryID).metaAD.replacedAt.IsZero() {
		t.Fatalf("replaced-key window was not stamped by the re-mint")
	}
	// The minted key dies much later, outside the 24h window.
	exec.mu.Lock()
	exec.invalid[minted] = struct{}{}
	exec.mu.Unlock()
	m.mu.Lock()
	m.auths[metaADPrimaryID].metaAD.replacedAt = time.Now().Add(-metaADReplacedKeyWindow - time.Hour)
	m.mu.Unlock()

	resp, err := metaADExecute(m, metaADModelA)
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}
	if got := string(resp.Payload); got != metaADPrimaryID+":minted-key-2" {
		t.Fatalf("payload = %q, want primary served by a re-minted key", got)
	}
	if got := exec.RefreshCalls(); got != 2 {
		t.Fatalf("Refresh calls = %d, want 2 (normal re-mint, not new_key_rejected)", got)
	}
	metaADRequireNotTracked(t, metaADGet(t, m, metaADPrimaryID))
}

func TestMetaAutoDisable_FreshLoginFirstRejectionMintsNormally(t *testing.T) {
	exec := newMetaADTestExecutor("dead-key-0")
	primary := metaADPrimary()
	primary.Metadata["last_refresh"] = time.Now().UTC().Format(time.RFC3339)
	primary.LastRefreshedAt = time.Now()
	m := newMetaADManager(t, true, exec, primary, metaADBackup())

	resp, err := metaADExecute(m, metaADModelA)
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}
	if got := string(resp.Payload); got != metaADPrimaryID+":minted-key-1" {
		t.Fatalf("payload = %q, want primary served by the minted key", got)
	}
	if got := exec.RefreshCalls(); got != 1 {
		t.Fatalf("Refresh calls = %d, want 1", got)
	}
	if got := exec.CallsFor(metaADPrimaryID); got != 2 {
		t.Fatalf("primary upstream calls = %d, want 2", got)
	}
	metaADRequireNotTracked(t, metaADGet(t, m, metaADPrimaryID))
	if raw := metaADRawState(m, metaADPrimaryID); raw.replacedKey == "" || time.Since(raw.replacedAt) > 10*time.Second || raw.replacedAt.After(time.Now()) {
		t.Fatalf("raw metaAD = %+v, want the replaced-key window stamped just now", raw)
	}
}

func metaADDCAOnlyAuth() *Auth {
	return &Auth{ID: metaADPrimaryID, Provider: "meta", Metadata: map[string]any{"dca_token": "dca:primary"}}
}

func TestMetaAutoDisable_PrepareRequestAuthMintRejectionEntersPending(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(fmt.Sprintf("mint_%d", status), func(t *testing.T) {
			exec := &metaADPreparerExecutor{metaADTestExecutor: newMetaADTestExecutor()}
			exec.enqueue(metaADRefreshResult{err: metaADMintErr(status)})
			m := newMetaADManager(t, true, exec, metaADDCAOnlyAuth(), metaADBackup())

			before := time.Now()
			resp, err := metaADExecute(m, metaADModelA)
			after := time.Now()
			if err != nil {
				t.Fatalf("Execute error = %v, want success via backup", err)
			}
			if got := string(resp.Payload); got != metaADBackupID+":good-key" {
				t.Fatalf("payload = %q, want backup response", got)
			}
			if exec.prepareCalls != 1 || exec.RefreshCalls() != 1 {
				t.Fatalf("prepare calls = %d, mint calls = %d, want 1 and 1", exec.prepareCalls, exec.RefreshCalls())
			}
			got := metaADGet(t, m, metaADPrimaryID)
			metaADRequireTracked(t, got, metaADStatePending, metaADReasonMintRejected)
			metaADRequireBlockedShape(t, got, "")
			metaADRequireDueIn(t, got, before, after, metaADConfirmDelay)
			metaADRequireBlockedEverywhere(t, got)
		})
	}
}

func TestMetaAutoDisable_PrepareRequestAuthTransientFailureIsNotTracked(t *testing.T) {
	cases := map[string]error{
		"mint_500": metaADMintErr(http.StatusInternalServerError),
		"network":  metaADNetworkErr(),
	}
	for name, mintErr := range cases {
		t.Run(name, func(t *testing.T) {
			exec := &metaADPreparerExecutor{metaADTestExecutor: newMetaADTestExecutor()}
			exec.enqueue(metaADRefreshResult{err: mintErr})
			m := newMetaADManager(t, true, exec, metaADDCAOnlyAuth(), metaADBackup())
			if _, err := metaADExecute(m, metaADModelA); err != nil {
				t.Fatalf("Execute error = %v, want success via backup", err)
			}
			if exec.prepareCalls != 1 {
				t.Fatalf("prepare calls = %d, want 1", exec.prepareCalls)
			}
			metaADRequireNotTracked(t, metaADGet(t, m, metaADPrimaryID))
		})
	}
}

func TestMetaAutoDisable_CredentialChangeCancelsTracking(t *testing.T) {
	t.Run("replaced credentials", func(t *testing.T) {
		m, _ := metaADEnterPendingViaRequest(t, http.StatusUnauthorized)
		metaADRequireTracked(t, metaADGet(t, m, metaADPrimaryID), metaADStatePending, metaADReasonMintRejected)

		replaced := &Auth{
			ID:       metaADPrimaryID,
			Provider: "meta",
			Metadata: map[string]any{"access_token": "relogin-key", "api_key": "relogin-key", "dca_token": "dca:relogin"},
		}
		if _, err := m.Update(context.Background(), replaced); err != nil {
			t.Fatalf("Update: %v", err)
		}
		got := metaADGet(t, m, metaADPrimaryID)
		metaADRequireNotTracked(t, got)
		if got.Unavailable {
			t.Fatalf("Unavailable = true after a credential replacement, want false")
		}
		now := time.Now()
		for _, model := range []string{metaADModelA, metaADModelB, ""} {
			if blocked, _, _ := isAuthBlockedForModel(got, model, now); blocked {
				t.Fatalf("auth still blocked for model %q after credential replacement", model)
			}
		}
	})

	t.Run("unchanged credentials", func(t *testing.T) {
		m, _ := metaADEnterPendingViaRequest(t, http.StatusUnauthorized)
		before := metaADGet(t, m, metaADPrimaryID)
		_, _, sinceBefore, _ := before.MetaAutoDisableStatus()

		// Same credential values as the live auth: a plain reload.
		reload := metaADPrimary()
		if _, err := m.Update(context.Background(), reload); err != nil {
			t.Fatalf("Update: %v", err)
		}
		got := metaADGet(t, m, metaADPrimaryID)
		metaADRequireTracked(t, got, metaADStatePending, metaADReasonMintRejected)
		if _, _, since, _ := got.MetaAutoDisableStatus(); !since.Equal(sinceBefore) {
			t.Fatalf("since changed across a reload: %v -> %v", sinceBefore, since)
		}
		if blocked, _, _ := isAuthBlockedForModel(got, metaADModelB, time.Now()); !blocked {
			t.Fatalf("tracked auth no longer blocked after a reload")
		}
	})
}

func TestMetaAutoDisable_ForcedRefreshMintRejectionDoesNotEnterPending(t *testing.T) {
	exec := newMetaADTestExecutor()
	exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
	m := newMetaADManager(t, true, exec, metaADPrimary(), metaADBackup())

	if _, err := m.ForceRefreshAuth(context.Background(), metaADPrimaryID); err == nil {
		t.Fatalf("ForceRefreshAuth error = nil, want the mint error")
	}
	if got := exec.RefreshCalls(); got != 1 {
		t.Fatalf("Refresh calls = %d, want 1", got)
	}
	metaADRequireNotTracked(t, metaADGet(t, m, metaADPrimaryID))
}

func metaADConfigKeyAuth(withDCA bool) *Auth {
	a := &Auth{
		ID:         metaADPrimaryID,
		Provider:   "meta",
		Attributes: map[string]string{"api_key": "dead-key-0", AttributeSource: "config:meta[abc123]"},
		Metadata:   map[string]any{"access_token": "dead-key-0", "api_key": "dead-key-0"},
	}
	if withDCA {
		a.Metadata["dca_token"] = "dca:primary"
	}
	return a
}

func TestMetaAutoDisable_ConfigKeyIsExcluded(t *testing.T) {
	type outcome struct {
		unavailable bool
		status      Status
		refreshSet  bool
		hasUnauth   bool
		refreshes   int
		primary     int
		message     string
	}
	run := func(t *testing.T, enabled, withDCA bool) outcome {
		t.Helper()
		if !IsConfigAPIKeyAuth(metaADConfigKeyAuth(withDCA)) {
			t.Fatalf("fixture is not a config API key auth")
		}
		exec := newMetaADTestExecutor("dead-key-0")
		exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
		m := newMetaADManager(t, enabled, exec, metaADConfigKeyAuth(withDCA), metaADBackup())
		if _, err := metaADExecute(m, metaADModelA); err != nil {
			t.Fatalf("Execute error = %v, want success via backup", err)
		}
		got := metaADGet(t, m, metaADPrimaryID)
		if got.metaAD.state != "" {
			t.Fatalf("metaAD = %+v, want empty for a config key", got.metaAD)
		}
		metaADRequireNotTracked(t, got)
		if metaADBlocks(got) {
			t.Fatalf("metaADBlocks = true for a config key")
		}
		return outcome{got.Unavailable, got.Status, !got.NextRefreshAfter.IsZero(), hasUnauthorizedAuthFailure(got), exec.RefreshCalls(), exec.CallsFor(metaADPrimaryID), got.StatusMessage}
	}
	for _, withDCA := range []bool{false, true} {
		t.Run(fmt.Sprintf("dca_%v", withDCA), func(t *testing.T) {
			on := run(t, true, withDCA)
			off := run(t, false, withDCA)
			if on != off {
				t.Fatalf("switch ON result %+v differs from switch OFF result %+v", on, off)
			}
		})
	}
}

func TestMetaAutoDisable_SwitchOffNeverCreatesState(t *testing.T) {
	m, exec := func() (*Manager, *metaADTestExecutor) {
		exec := newMetaADTestExecutor("dead-key-0")
		exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
		m := newMetaADManager(t, false, exec, metaADPrimary(), metaADBackup())
		if _, err := metaADExecute(m, metaADModelA); err != nil {
			t.Fatalf("Execute error = %v, want success via backup", err)
		}
		return m, exec
	}()
	got := metaADGet(t, m, metaADPrimaryID)
	metaADRequireNotTracked(t, got)
	if got.metaAD.state != "" || got.metaAD.replacedKey != "" {
		t.Fatalf("metaAD = %+v, want empty with the switch off", got.metaAD)
	}
	// Existing behaviour: a mint 401 is a terminal unauthorized failure.
	if !got.Unavailable || got.Status != StatusError || !hasUnauthorizedAuthFailure(got) || !got.NextRefreshAfter.IsZero() {
		t.Fatalf("unavailable=%v status=%v terminal401=%v nextRefresh=%v, want the legacy terminal unauthorized state", got.Unavailable, got.Status, hasUnauthorizedAuthFailure(got), got.NextRefreshAfter)
	}
	if exec.RefreshCalls() != 1 {
		t.Fatalf("Refresh calls = %d, want 1", exec.RefreshCalls())
	}
}

func TestMetaAutoDisable_HotReloadOffToOnTracksNextRejection(t *testing.T) {
	exec := newMetaADTestExecutor("dead-key-0")
	exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
	second := &Auth{
		ID:       "cc-meta-second",
		Provider: "meta",
		Metadata: map[string]any{"access_token": "dead-key-2", "api_key": "dead-key-2", "dca_token": "dca:second"},
	}
	m := newMetaADManager(t, false, exec, metaADPrimary(), second, metaADBackup())
	if _, err := metaADExecute(m, metaADModelA); err != nil {
		t.Fatalf("Execute error = %v, want success via a healthy auth", err)
	}
	metaADRequireNotTracked(t, metaADGet(t, m, metaADPrimaryID))

	m.SetConfig(metaADSwitch(true))
	exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
	live := metaADGet(t, m, second.ID)
	if _, retried := m.tryRefreshAfterUnauthorized(context.Background(), live, &Error{HTTPStatus: http.StatusUnauthorized}, false); retried {
		t.Fatalf("recovery retried, want a failed mint")
	}
	metaADRequireTracked(t, metaADGet(t, m, second.ID), metaADStatePending, metaADReasonMintRejected)
}

func TestMetaAutoDisable_HotReloadOnToOffCancelsTracking(t *testing.T) {
	m, exec := metaADEnterPendingViaRequest(t, http.StatusUnauthorized)
	metaADRequireTracked(t, metaADGet(t, m, metaADPrimaryID), metaADStatePending, metaADReasonMintRejected)

	m.SetConfig(metaADSwitch(false))
	exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
	metaADConfirmDue(m, metaADPrimaryID)

	got := metaADGet(t, m, metaADPrimaryID)
	metaADRequireNotTracked(t, got)
	if got.metaAD.state != "" {
		t.Fatalf("metaAD = %+v, want cleared after the switch went off", got.metaAD)
	}
	if strings.HasPrefix(got.StatusMessage, "meta auto-disable") {
		t.Fatalf("StatusMessage = %q, want the generic handling to have taken over", got.StatusMessage)
	}
	if got := exec.RefreshCalls(); got != 2 {
		t.Fatalf("Refresh calls = %d, want 2 (generic handling still mints)", got)
	}
}

func TestMetaAutoDisable_LogsReasonWithoutSecrets(t *testing.T) {
	hook := setupTestLoggerHook(t)
	m, exec := metaADEnterPendingViaRequest(t, http.StatusUnauthorized)
	exec.enqueue(metaADRefreshResult{err: metaADNetworkErr()})
	metaADConfirmDue(m, metaADPrimaryID)
	exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
	metaADConfirmDue(m, metaADPrimaryID)

	foundPending := false
	secrets := []string{"dead-key-0", "dca:primary", "good-key", "dca:backup", "minted-key"}
	for _, entry := range hook.AllEntries() {
		line := entry.Message + " " + fmt.Sprint(entry.Data)
		for _, secret := range secrets {
			if strings.Contains(line, secret) {
				t.Fatalf("log line leaks %q: %s", secret, line)
			}
		}
		if entry.Level == log.WarnLevel && strings.Contains(line, metaADPrimaryID) && strings.Contains(line, metaADReasonMintRejected) && strings.Contains(entry.Message, "awaiting confirmation") {
			foundPending = true
		}
	}
	if !foundPending {
		t.Fatalf("no WARN pending entry with auth id and reason; entries: %#v", hook.AllEntries())
	}
}

func TestMetaAutoDisable_CloneCopiesStateAndJSONOmitsIt(t *testing.T) {
	m, _ := metaADEnterPendingViaRequest(t, http.StatusUnauthorized)
	orig := metaADGet(t, m, metaADPrimaryID)
	clone := orig.Clone()
	s1, r1, since1, ok1 := orig.MetaAutoDisableStatus()
	s2, r2, since2, ok2 := clone.MetaAutoDisableStatus()
	if !ok1 || !ok2 || s1 != s2 || r1 != r2 || !since1.Equal(since2) {
		t.Fatalf("clone status = (%q,%q,%v,%v), want (%q,%q,%v,%v)", s2, r2, since2, ok2, s1, r1, since1, ok1)
	}
	clone.metaAD.confirmed = true
	if orig.metaAD.confirmed {
		t.Fatalf("mutating the clone's state changed the original")
	}

	only := &Auth{ID: "x", Provider: "meta"}
	only.metaAD = metaAutoDisableState{state: metaADStatePending, reason: metaADReasonMintRejected, since: time.Now(), cred: metaADFingerprint(only), confirmed: true}
	raw, err := json.Marshal(only)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	for _, word := range []string{"pending", "mint_rejected", "confirmed", "metaAD", "metaad"} {
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(word)) {
			t.Fatalf("JSON %s contains %q", raw, word)
		}
	}
}

// newMetaADTrackedAuth returns a standalone auth in the tracked state, with the
// shape metaADEnterPending leaves.
func newMetaADTrackedAuth(id, provider string) *Auth {
	a := &Auth{
		ID:       id,
		Provider: provider,
		Metadata: map[string]any{"access_token": "k", "api_key": "k", "dca_token": "dca:x"},
	}
	metaADEnterPending(a, metaADReasonMintRejected, time.Now())
	return a
}

func TestMetaAutoDisable_SelectionHookBlocksEveryModel(t *testing.T) {
	now := time.Now()

	t.Run("tracked auth with model state and expired retry", func(t *testing.T) {
		a := newMetaADTrackedAuth(metaADPrimaryID, "meta")
		a.NextRetryAfter = now.Add(-time.Minute)
		a.ModelStates = map[string]*ModelState{metaADModelA: {Status: StatusActive}}
		for _, model := range []string{metaADModelA, metaADModelB, ""} {
			if blocked, _, _ := isAuthBlockedForModel(a, model, now); !blocked {
				t.Fatalf("tracked auth not blocked for model %q", model)
			}
		}
	})

	t.Run("hook does not touch other auths", func(t *testing.T) {
		healthy := func(a *Auth) *Auth {
			a.Unavailable, a.Status, a.StatusMessage, a.LastError = false, StatusActive, "", nil
			a.NextRefreshAfter, a.NextRetryAfter = time.Time{}, time.Time{}
			return a
		}
		cases := map[string]*Auth{
			"untracked meta":           healthy(&Auth{ID: "u", Provider: "meta", Metadata: map[string]any{"access_token": "k"}}),
			"tracked-looking non-meta": healthy(newMetaADTrackedAuth("n", "codex")),
			"config key": healthy(func() *Auth {
				a := metaADConfigKeyAuth(true)
				metaADEnterPending(a, metaADReasonMintRejected, now)
				return a
			}()),
		}
		for name, a := range cases {
			for _, model := range []string{metaADModelA, ""} {
				if blocked, _, _ := isAuthBlockedForModel(a, model, now); blocked {
					t.Fatalf("%s: blocked for model %q, want selection unchanged", name, model)
				}
			}
		}
	})

	t.Run("manager never picks the tracked primary", func(t *testing.T) {
		m, exec := metaADEnterPendingViaRequest(t, http.StatusUnauthorized)
		before := exec.CallsFor(metaADPrimaryID)
		for i := 0; i < 4; i++ {
			model := metaADModelB
			if i%2 == 1 {
				model = metaADModelC
			}
			resp, err := metaADExecute(m, model)
			if err != nil {
				t.Fatalf("Execute %d: %v", i, err)
			}
			if got := string(resp.Payload); got != metaADBackupID+":good-key" {
				t.Fatalf("Execute %d payload = %q, want backup", i, got)
			}
		}
		if got := exec.CallsFor(metaADPrimaryID); got != before {
			t.Fatalf("tracked primary received %d extra upstream calls, want 0", got-before)
		}
	})
}

func TestMetaAutoDisable_RefreshScheduleHookKeepsDueConfirmation(t *testing.T) {
	m, exec := metaADEnterPendingViaRequest(t, http.StatusUnauthorized)
	metaADMakeDue(m, metaADPrimaryID)
	due := metaADGet(t, m, metaADPrimaryID)

	now := time.Now()
	next, schedule := nextRefreshCheckAt(now, due, time.Second)
	if !schedule || next.After(now) {
		t.Fatalf("nextRefreshCheckAt = (%v, %v), want (<= now, true)", next, schedule)
	}
	if !m.shouldRefresh(due, now) {
		t.Fatalf("shouldRefresh = false for a due tracked auth")
	}

	// Through the loop: the due auth is enqueued and the job runs the confirmation.
	ctx := context.Background()
	l := newAuthAutoRefreshLoop(m, time.Second, 1)
	l.handleDueAuth(ctx, now, metaADPrimaryID)
	var job *authRefreshJob
	select {
	case job = <-l.jobs:
	default:
		t.Fatalf("no refresh job enqueued for a due tracked auth")
	}
	if job == nil {
		t.Fatalf("nil refresh job")
	}
	if m.beginRefreshJob(ctx, job) {
		_, _ = m.refreshAuthForRequestAtEpoch(ctx, job.id, "", job.registrationEpoch)
	}
	m.finishRefreshJob(job, time.Time{}, false)

	if got := exec.RefreshCalls(); got != 2 {
		t.Fatalf("Refresh calls = %d, want 2 (the confirmation ran)", got)
	}
	metaADRequireNotTracked(t, metaADGet(t, m, metaADPrimaryID))
}

func TestMetaAutoDisable_ConfirmedAuthLeavesRefreshLoop(t *testing.T) {
	m, exec := metaADEnterPendingViaRequest(t, http.StatusUnauthorized)
	exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
	metaADConfirmDue(m, metaADPrimaryID)

	// Once the parked hold has passed, a confirmed auth is neither scheduled nor refreshed.
	metaADMakeDue(m, metaADPrimaryID)
	parked := metaADGet(t, m, metaADPrimaryID)
	if !parked.metaAD.confirmed {
		t.Fatalf("precondition: auth is not confirmed")
	}
	now := time.Now()
	if next, schedule := nextRefreshCheckAt(now, parked, time.Second); schedule || !next.IsZero() {
		t.Fatalf("nextRefreshCheckAt = (%v, %v), want (zero, false)", next, schedule)
	}
	if m.shouldRefresh(parked, now) {
		t.Fatalf("shouldRefresh = true for a confirmed auth")
	}
	l := newAuthAutoRefreshLoop(m, time.Second, 1)
	l.handleDueAuth(context.Background(), now, metaADPrimaryID)
	select {
	case job := <-l.jobs:
		t.Fatalf("unexpected refresh job for a confirmed auth: %+v", job)
	default:
	}
}

func TestMetaAutoDisable_SwitchOffRequestMintLeavesNoReplacedStamp(t *testing.T) {
	exec := newMetaADTestExecutor("dead-key-0")
	m := newMetaADManager(t, false, exec, metaADPrimary(), metaADBackup())
	resp, err := metaADExecute(m, metaADModelA)
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}
	if got := string(resp.Payload); got != metaADPrimaryID+":minted-key-1" {
		t.Fatalf("payload = %q, want primary served by the minted key", got)
	}
	if raw := metaADRawState(m, metaADPrimaryID); raw.replacedKey != "" || !raw.replacedAt.IsZero() || raw.state != "" {
		t.Fatalf("raw metaAD = %+v, want empty with the switch off", raw)
	}
}

func TestMetaAutoDisable_ConfirmationMintReturningRejectedKeyRetries(t *testing.T) {
	m, exec := metaADEnterPendingViaRequest(t, http.StatusUnauthorized)
	m.mu.RLock()
	rejected := m.auths[metaADPrimaryID].RejectedAccessToken
	m.mu.RUnlock()
	if rejected != "dead-key-0" {
		t.Fatalf("precondition: RejectedAccessToken = %q, want dead-key-0", rejected)
	}

	// The mint succeeds but returns the key upstream already rejected.
	for i, want := range []time.Duration{5 * time.Minute, 15 * time.Minute} {
		exec.enqueue(metaADRefreshResult{sameKey: true})
		before := time.Now()
		metaADConfirmDue(m, metaADPrimaryID)
		after := time.Now()

		if got := exec.RefreshCalls(); got != 2+i {
			t.Fatalf("run %d: Refresh calls = %d, want %d", i+1, got, 2+i)
		}
		got := metaADGet(t, m, metaADPrimaryID)
		if _, _, _, ok := got.MetaAutoDisableStatus(); !ok && i == 0 {
			// The generic refresh commit clears RejectedAccessToken when the mint hands back the
			// same key, so the retry decision must rest on the unchanged credential fingerprint.
			t.Fatalf("same-key mint restores instead of retrying: RejectedAccessToken=%q unavailable=%v nextRefresh=%v", got.RejectedAccessToken, got.Unavailable, got.NextRefreshAfter)
		}
		metaADRequireTracked(t, got, metaADStateRetry, metaADReasonMintRejected)
		metaADRequireBlockedShape(t, got, metaADReasonMintRejected)
		metaADRequireBlockedEverywhere(t, got)
		metaADRequireDueIn(t, got, before, after, want)
		if got.metaAD.confirmed {
			t.Fatalf("run %d: must not be confirmed", i+1)
		}
		if m.shouldRefresh(got, time.Now()) {
			t.Fatalf("run %d: shouldRefresh = true before the retry delay elapsed (would hammer)", i+1)
		}
		if next, schedule := nextRefreshCheckAt(time.Now(), got, time.Second); !schedule || !next.Equal(got.NextRefreshAfter) {
			t.Fatalf("run %d: nextRefreshCheckAt = (%v, %v), want (NextRefreshAfter, true)", i+1, next, schedule)
		}
	}
}

func TestMetaAutoDisable_ConfirmationRejectedKeyWithSwitchOffClearsTracking(t *testing.T) {
	m, exec := metaADEnterPendingViaRequest(t, http.StatusUnauthorized)
	m.SetConfig(metaADSwitch(false))
	exec.enqueue(metaADRefreshResult{sameKey: true})
	metaADConfirmDue(m, metaADPrimaryID)

	if raw := metaADRawState(m, metaADPrimaryID); raw.state != "" {
		t.Fatalf("raw metaAD = %+v, want tracking cleared with the switch off", raw)
	}
	metaADRequireNotTracked(t, metaADGet(t, m, metaADPrimaryID))
}

// metaADBlockedRefresh starts fn in a goroutine and waits until the executor's Refresh
// (or PrepareRequestAuth) is in flight and blocked. The returned release lets it go;
// wait returns what fn returned.
func metaADBlockedRefresh(t *testing.T, exec *metaADTestExecutor, fn func() error) (release func(), wait func() error) {
	t.Helper()
	exec.mu.Lock()
	exec.refreshEntered = make(chan struct{}, 4)
	exec.refreshRelease = make(chan struct{})
	entered, rel := exec.refreshEntered, exec.refreshRelease
	exec.mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- fn() }()
	<-entered
	return func() { close(rel) }, func() error { return <-done }
}

func metaADReplacementAuth(withDCA bool) *Auth {
	a := &Auth{
		ID:       metaADPrimaryID,
		Provider: "meta",
		Metadata: map[string]any{"access_token": "login-key-9", "api_key": "login-key-9"},
	}
	if withDCA {
		a.Metadata["dca_token"] = "dca:login"
	}
	return a
}

// metaADRequireUntouched asserts the live credential carries no auto-disable effect.
func metaADRequireUntouched(t *testing.T, m *Manager, id string) {
	t.Helper()
	got := metaADGet(t, m, id)
	metaADRequireNotTracked(t, got)
	if raw := metaADRawState(m, id); raw.state != "" {
		t.Fatalf("raw metaAD = %+v, want no tracking", raw)
	}
	if got.Unavailable || !got.NextRefreshAfter.IsZero() {
		t.Fatalf("unavailable=%v nextRefresh=%v, want an untouched credential", got.Unavailable, got.NextRefreshAfter)
	}
	for _, model := range []string{metaADModelA, metaADModelB, ""} {
		if blocked, _, _ := isAuthBlockedForModel(got, model, time.Now()); blocked {
			t.Fatalf("credential blocked for model %q, want selectable", model)
		}
	}
}

func TestMetaAutoDisable_StaleMintFailureAfterCredentialReplacementIsIgnored(t *testing.T) {
	for _, withDCA := range []bool{true, false} {
		t.Run(fmt.Sprintf("replacement_dca_%v", withDCA), func(t *testing.T) {
			exec := newMetaADTestExecutor()
			exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
			m := newMetaADManager(t, true, exec, metaADPrimary(), metaADBackup())

			release, wait := metaADBlockedRefresh(t, exec, func() error {
				_, err := m.refreshAuthForRequest(context.Background(), metaADPrimaryID, "dead-key-0")
				return err
			})
			if _, err := m.Update(context.Background(), metaADReplacementAuth(withDCA)); err != nil {
				t.Fatalf("Update: %v", err)
			}
			release()
			if err := wait(); err == nil {
				t.Fatalf("refresh error = nil, want the mint error")
			}

			if got := exec.RefreshCalls(); got != 1 {
				t.Fatalf("Refresh calls = %d, want 1", got)
			}
			metaADRequireUntouched(t, m, metaADPrimaryID)
			if !withDCA {
				// Nothing is stuck in retry: a later refresh neither tracks nor changes the key.
				m.refreshAuth(context.Background(), metaADPrimaryID)
				metaADRequireUntouched(t, m, metaADPrimaryID)
				live := metaADGet(t, m, metaADPrimaryID)
				if key := metaADKey(live); key != "login-key-9" {
					t.Fatalf("key = %q, want login-key-9 (nothing was minted)", key)
				}
				if m.shouldRefresh(live, time.Now()) {
					t.Fatalf("shouldRefresh = true for the replacement, want false")
				}
			}
		})
	}
}

func TestMetaAutoDisable_StaleMintFailureAfterEpochChangeIsIgnored(t *testing.T) {
	exec := newMetaADTestExecutor()
	exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)})
	m := newMetaADManager(t, true, exec, metaADPrimary(), metaADBackup())

	release, wait := metaADBlockedRefresh(t, exec, func() error {
		_, err := m.refreshAuthForRequest(context.Background(), metaADPrimaryID, "dead-key-0")
		return err
	})
	// Same key and dca_token, new registration epoch.
	epochBefore := metaADGet(t, m, metaADPrimaryID).RegistrationEpoch
	m.Remove(context.Background(), metaADPrimaryID)
	if _, err := m.Register(context.Background(), metaADPrimary()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if epochAfter := metaADGet(t, m, metaADPrimaryID).RegistrationEpoch; epochAfter == epochBefore {
		t.Fatalf("precondition: registration epoch did not change (%d)", epochAfter)
	}
	release()
	if err := wait(); err == nil {
		t.Fatalf("refresh error = nil, want the mint error")
	}
	metaADRequireUntouched(t, m, metaADPrimaryID)
}

func TestMetaAutoDisable_StalePrepareFailureAfterReplacementIsIgnored(t *testing.T) {
	replace := map[string]func(t *testing.T, m *Manager){
		"credential changed": func(t *testing.T, m *Manager) {
			a := &Auth{ID: metaADPrimaryID, Provider: "meta", Metadata: map[string]any{"dca_token": "dca:login"}}
			if _, err := m.Update(context.Background(), a); err != nil {
				t.Fatalf("Update: %v", err)
			}
		},
		"epoch changed": func(t *testing.T, m *Manager) {
			m.Remove(context.Background(), metaADPrimaryID)
			if _, err := m.Register(context.Background(), metaADDCAOnlyAuth()); err != nil {
				t.Fatalf("Register: %v", err)
			}
		},
	}
	for name, doReplace := range replace {
		t.Run(name, func(t *testing.T) {
			exec := &metaADPreparerExecutor{metaADTestExecutor: newMetaADTestExecutor()}
			exec.enqueue(metaADRefreshResult{err: metaADMintErr(http.StatusForbidden)})
			m := newMetaADManager(t, true, exec, metaADDCAOnlyAuth(), metaADBackup())

			release, wait := metaADBlockedRefresh(t, exec.metaADTestExecutor, func() error {
				_, err := m.PrepareRequestAuth(context.Background(), exec, metaADGet(t, m, metaADPrimaryID))
				return err
			})
			doReplace(t, m)
			release()
			if err := wait(); err == nil {
				t.Fatalf("prepare error = nil, want the mint error")
			}
			metaADRequireUntouched(t, m, metaADPrimaryID)
		})
	}
}

func TestMetaAutoDisable_TrackedCredentialWithoutDCATokenIsReleased(t *testing.T) {
	exec := newMetaADTestExecutor()
	primary := &Auth{
		ID:       metaADPrimaryID,
		Provider: "meta",
		Metadata: map[string]any{"access_token": "dead-key-0", "api_key": "dead-key-0"},
	}
	m := newMetaADManager(t, true, exec, primary, metaADBackup())
	m.mu.Lock()
	metaADEnterPending(m.auths[metaADPrimaryID], metaADReasonMintRejected, time.Now())
	m.mu.Unlock()
	metaADRequireTracked(t, metaADGet(t, m, metaADPrimaryID), metaADStatePending, metaADReasonMintRejected)

	metaADConfirmDue(m, metaADPrimaryID)

	if got := exec.RefreshCalls(); got != 0 {
		t.Fatalf("Refresh calls = %d, want 0 (nothing to mint with)", got)
	}
	metaADRequireUntouched(t, m, metaADPrimaryID)
}

func TestMetaAutoDisable_StaleMintSuccessDoesNotStampReplacementKey(t *testing.T) {
	t.Run("credential replaced during the mint", func(t *testing.T) {
		exec := newMetaADTestExecutor("dead-key-0", "login-key-9")
		m := newMetaADManager(t, true, exec, metaADPrimary(), metaADBackup())

		release, wait := metaADBlockedRefresh(t, exec, func() error {
			_, err := m.refreshAuthForRequest(context.Background(), metaADPrimaryID, "dead-key-0")
			return err
		})
		if _, err := m.Update(context.Background(), metaADReplacementAuth(true)); err != nil {
			t.Fatalf("Update: %v", err)
		}
		release()
		_ = wait()

		live := metaADGet(t, m, metaADPrimaryID)
		if key := metaADKey(live); key != "login-key-9" {
			t.Fatalf("live key = %q, want the replacement login-key-9", key)
		}
		if raw := metaADRawState(m, metaADPrimaryID); raw.replacedKey != "" || !raw.replacedAt.IsZero() {
			t.Fatalf("raw metaAD = %+v, a discarded mint must not stamp the replacement key", raw)
		}

		// The first rejection of the new key mints normally instead of reading as new_key_rejected.
		refreshesBefore := exec.RefreshCalls()
		resp, err := metaADExecute(m, metaADModelA)
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if got := string(resp.Payload); got != metaADPrimaryID+":minted-key-2" {
			t.Fatalf("payload = %q, want the primary served by a fresh mint", got)
		}
		if got := exec.RefreshCalls(); got != refreshesBefore+1 {
			t.Fatalf("Refresh calls = %d, want %d (a normal re-mint)", got, refreshesBefore+1)
		}
		metaADRequireNotTracked(t, metaADGet(t, m, metaADPrimaryID))
	})

	t.Run("positive control without replacement", func(t *testing.T) {
		exec := newMetaADTestExecutor("dead-key-0")
		m := newMetaADManager(t, true, exec, metaADPrimary(), metaADBackup())
		if _, err := m.refreshAuthForRequest(context.Background(), metaADPrimaryID, "dead-key-0"); err != nil {
			t.Fatalf("refresh: %v", err)
		}
		raw := metaADRawState(m, metaADPrimaryID)
		if raw.replacedKey != metaADTokenFingerprint("minted-key-1") || raw.replacedAt.IsZero() {
			t.Fatalf("raw metaAD = %+v, want the minted key stamped", raw)
		}
	})
}

func TestMetaAutoDisable_ConcurrentRejectionsDoNotBypassConfirmationDelay(t *testing.T) {
	exec := newMetaADTestExecutor()
	exec.enqueue(
		metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)},
		metaADRefreshResult{err: metaADMintErr(http.StatusUnauthorized)},
		metaADRefreshResult{},
	)
	m := newMetaADManager(t, true, exec, metaADPrimary(), metaADBackup())

	before := time.Now()
	release, waitFirst := metaADBlockedRefresh(t, exec, func() error {
		_, err := m.refreshAuthForRequest(context.Background(), metaADPrimaryID, "dead-key-0")
		return err
	})
	second := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(second)
		_, err := m.refreshAuthForRequest(context.Background(), metaADPrimaryID, "dead-key-0")
		secondDone <- err
	}()
	<-second
	for i := 0; i < 100; i++ {
		runtime.Gosched()
	}
	release()
	errFirst, errSecond := waitFirst(), <-secondDone
	after := time.Now()

	errs := []error{errFirst, errSecond}
	awaiting, mintRejected := 0, 0
	for _, err := range errs {
		switch {
		case errors.Is(err, errMetaAutoDisableAwaiting):
			awaiting++
		case metaADMintRejected(err):
			mintRejected++
		default:
			t.Fatalf("unexpected refresh error %v", err)
		}
	}
	if awaiting != 1 || mintRejected != 1 {
		t.Fatalf("errors = %v, want one mint rejection and one awaiting error", errs)
	}
	if got := exec.RefreshCalls(); got != 1 {
		t.Fatalf("Refresh calls = %d, want exactly 1", got)
	}
	got := metaADGet(t, m, metaADPrimaryID)
	metaADRequireTracked(t, got, metaADStatePending, metaADReasonMintRejected)
	if raw := metaADRawState(m, metaADPrimaryID); raw.attempts != 0 || raw.confirmed {
		t.Fatalf("raw metaAD = %+v, want pending with no attempts and not confirmed", raw)
	}
	metaADRequireDueIn(t, got, before, after, metaADConfirmDelay)

	// Sequential variant: another request-path refresh is refused without calling the executor.
	if _, err := m.refreshAuthForRequest(context.Background(), metaADPrimaryID, "dead-key-0"); !errors.Is(err, errMetaAutoDisableAwaiting) {
		t.Fatalf("sequential refresh error = %v, want errMetaAutoDisableAwaiting", err)
	}
	if got := exec.RefreshCalls(); got != 1 {
		t.Fatalf("Refresh calls after the sequential request = %d, want 1", got)
	}
}
