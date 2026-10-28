package auth

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const (
	metaRemintPrimaryID = "aa-meta-primary"
	metaRemintBackupID  = "bb-meta-backup"
	metaRemintModelA    = "meta-model-a"
	metaRemintModelB    = "meta-model-b"
)

// metaRemintTestExecutor rejects every key of the primary (including freshly
// minted ones) with 401 and accepts the backup. Refresh mints a unique key.
type metaRemintTestExecutor struct {
	mu           sync.Mutex
	refreshCalls int
	primaryCalls int
}

func (e *metaRemintTestExecutor) Identifier() string { return "meta" }

func (e *metaRemintTestExecutor) call(auth *Auth) ([]byte, error) {
	if auth.ID == metaRemintPrimaryID {
		e.mu.Lock()
		e.primaryCalls++
		e.mu.Unlock()
		return nil, &Error{HTTPStatus: http.StatusUnauthorized, Message: "key rejected"}
	}
	return []byte(auth.ID), nil
}

func (e *metaRemintTestExecutor) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	payload, err := e.call(auth)
	return cliproxyexecutor.Response{Payload: payload}, err
}

func (e *metaRemintTestExecutor) ExecuteStream(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	payload, err := e.call(auth)
	if err != nil {
		return nil, err
	}
	ch := make(chan cliproxyexecutor.StreamChunk, 1)
	ch <- cliproxyexecutor.StreamChunk{Payload: payload}
	close(ch)
	return &cliproxyexecutor.StreamResult{Chunks: ch}, nil
}

func (e *metaRemintTestExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	e.mu.Lock()
	e.refreshCalls++
	n := e.refreshCalls
	e.mu.Unlock()
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = fmt.Sprintf("dead-key-%d", n)
	return auth, nil
}

func (e *metaRemintTestExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, &Error{HTTPStatus: http.StatusNotImplemented, Message: "not implemented"}
}

func (e *metaRemintTestExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func (e *metaRemintTestExecutor) RefreshCalls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.refreshCalls
}

func newMetaRemintFixture(t *testing.T) (*Manager, *metaRemintTestExecutor) {
	t.Helper()
	exec := &metaRemintTestExecutor{}
	m := NewManager(nil, nil, nil)
	m.RegisterExecutor(exec)

	reg := registry.GetGlobalRegistry()
	models := []*registry.ModelInfo{{ID: metaRemintModelA}, {ID: metaRemintModelB}}
	for _, a := range []*Auth{
		{ID: metaRemintPrimaryID, Provider: "meta", Metadata: map[string]any{"access_token": "dead-key-0", "dca_token": "dca:primary"}},
		{ID: metaRemintBackupID, Provider: "meta", Metadata: map[string]any{"access_token": "good-key", "dca_token": "dca:backup"}},
	} {
		id := a.ID
		reg.RegisterClient(id, "meta", models)
		t.Cleanup(func() { reg.UnregisterClient(id) })
		if _, err := m.Register(context.Background(), a); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}
	return m, exec
}

func TestMetaUnauthorizedRemintFrequency(t *testing.T) {
	m, exec := newMetaRemintFixture(t)

	run := func(label, model string) int {
		t.Helper()
		resp, err := m.Execute(context.Background(), []string{"meta"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
		if err != nil {
			t.Fatalf("%s: Execute error = %v, want success via backup", label, err)
		}
		if string(resp.Payload) != metaRemintBackupID {
			t.Fatalf("%s: payload = %q, want backup", label, resp.Payload)
		}
		p, _ := m.GetByID(metaRemintPrimaryID)
		var retry []string
		for name, st := range p.ModelStates {
			retry = append(retry, fmt.Sprintf("%s:unavail=%v,retry=%v", name, st.Unavailable, !st.NextRetryAfter.IsZero()))
		}
		t.Logf("%-10s model=%s primaryCalls=%d refreshes=%d unavailable=%v status=%s msg=%q nextRefresh=%v nextRetry=%v modelStates=%d [%s]",
			label, model, exec.primaryCalls, exec.RefreshCalls(), p.Unavailable, p.Status, p.StatusMessage,
			!p.NextRefreshAfter.IsZero(), !p.NextRetryAfter.IsZero(), len(p.ModelStates), strings.Join(retry, " "))
		return exec.RefreshCalls()
	}

	got := []int{
		run("1:A", metaRemintModelA),
		run("2:A", metaRemintModelA),
		run("3:B", metaRemintModelB),
		run("4:A", metaRemintModelA),
		run("5:B", metaRemintModelB),
	}

	// Only the first request mints (1 mint + 1 retry on the primary, both 401).
	// That 401 suspends the primary at auth level (~30 min NextRetryAfter), so
	// the selector skips it for every later request, on model A and on model B
	// alike; it is never tried again, hence never re-minted. (The ~5 min
	// NextRefreshAfter concerns the background refresher, not selection.)
	want := []int{1, 1, 1, 1, 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cumulative Refresh counts = %v, want %v", got, want)
	}
	if exec.primaryCalls != 2 {
		t.Fatalf("primary upstream calls = %d, want 2 (original + one retry with the minted key)", exec.primaryCalls)
	}
}

func TestMetaUnauthorizedSingleRequestMintsOnce(t *testing.T) {
	m, exec := newMetaRemintFixture(t)

	resp, err := m.Execute(context.Background(), []string{"meta"}, cliproxyexecutor.Request{Model: metaRemintModelA}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("Execute error = %v, want success via backup", err)
	}
	if string(resp.Payload) != metaRemintBackupID {
		t.Fatalf("payload = %q, want backup", resp.Payload)
	}
	if got := exec.RefreshCalls(); got != 1 {
		t.Fatalf("Refresh calls = %d, want exactly 1 (retry 401 must not mint again)", got)
	}
}
