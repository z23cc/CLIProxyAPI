package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	_ "github.com/router-for-me/CLIProxyAPI/v8/internal/translator"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

const musePinWireModel = "muse-pin-wire-model"

type musePinStatusErr struct{ status int }

func (e *musePinStatusErr) Error() string   { return "Billing verification failed" }
func (e *musePinStatusErr) StatusCode() int { return e.status }

// musePinFailingExecutor fails every call with the configured error and records the auth IDs it saw.
type musePinFailingExecutor struct {
	err   error
	mu    sync.Mutex
	calls []string
}

func (e *musePinFailingExecutor) Identifier() string { return "codex" }

func (e *musePinFailingExecutor) record(auth *cliproxyauth.Auth) {
	e.mu.Lock()
	e.calls = append(e.calls, auth.ID)
	e.mu.Unlock()
}

func (e *musePinFailingExecutor) Execute(_ context.Context, auth *cliproxyauth.Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.record(auth)
	return cliproxyexecutor.Response{}, e.err
}

func (e *musePinFailingExecutor) ExecuteStream(_ context.Context, auth *cliproxyauth.Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.record(auth)
	ch := make(chan cliproxyexecutor.StreamChunk, 1)
	ch <- cliproxyexecutor.StreamChunk{Err: e.err}
	close(ch)
	return &cliproxyexecutor.StreamResult{Chunks: ch}, nil
}

func (e *musePinFailingExecutor) Refresh(_ context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	return auth, nil
}

func (e *musePinFailingExecutor) CountTokens(context.Context, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, e.err
}

func (e *musePinFailingExecutor) HttpRequest(context.Context, *cliproxyauth.Auth, *http.Request) (*http.Response, error) {
	return nil, e.err
}

func TestResponsesMuseAccountPinWire(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name       string
		header     func(a, b *cliproxyauth.Auth) string
		upstream   int
		wantStatus int
		reason     string
		// pinnedAuthExecuted reports whether the pinned auth must have reached the executor.
		executed bool
	}{
		{name: "upstream_402", header: func(_, b *cliproxyauth.Auth) string { return b.Index }, upstream: 402, wantStatus: 409, reason: "payment_required", executed: true},
		{name: "upstream_403", header: func(_, b *cliproxyauth.Auth) string { return b.Index }, upstream: 403, wantStatus: 409, reason: "forbidden", executed: true},
		{name: "unknown_index", header: func(_, _ *cliproxyauth.Auth) string { return "deadbeefdeadbeef" }, upstream: 402, wantStatus: 409, reason: "not_found"},
		{name: "garbage_header", header: func(_, _ *cliproxyauth.Auth) string { return "Billing verification failed" }, upstream: 402, wantStatus: 409, reason: "not_found"},
		{name: "upstream_503_passthrough", header: func(_, b *cliproxyauth.Auth) string { return b.Index }, upstream: 503, wantStatus: 503, executed: true},
	}
	for _, stream := range []bool{false, true} {
		for _, tc := range cases {
			name := tc.name + "/non_stream"
			body := `{"model":"` + musePinWireModel + `","input":"hello","stream":false}`
			if stream {
				name = tc.name + "/stream"
				body = `{"model":"` + musePinWireModel + `","input":"hello","stream":true}`
			}
			t.Run(name, func(t *testing.T) {
				executor := &musePinFailingExecutor{err: &musePinStatusErr{status: tc.upstream}}
				manager := cliproxyauth.NewManager(nil, nil, nil)
				manager.RegisterExecutor(executor)
				prefix := strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
				var auths []*cliproxyauth.Auth
				for _, suffix := range []string{"-a", "-b"} {
					auth := &cliproxyauth.Auth{ID: prefix + suffix, Provider: "codex", Status: cliproxyauth.StatusActive, Metadata: map[string]any{"email": prefix + suffix}}
					if _, err := manager.Register(context.Background(), auth); err != nil {
						t.Fatal(err)
					}
					registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: musePinWireModel}})
					id := auth.ID
					t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
					auth.EnsureIndex()
					auths = append(auths, auth)
				}
				authA, authB := auths[0], auths[1]

				h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager))
				router := gin.New()
				router.Use(logging.GinLogrusLogger(), logging.CPATraceIDMiddleware())
				router.POST("/v1/responses", h.Responses)
				req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set(logging.MuseAccountHeader, tc.header(authA, authB))
				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, req)

				if recorder.Code == http.StatusUnauthorized {
					t.Fatal("status must never be 401")
				}
				if recorder.Code != tc.wantStatus {
					t.Fatalf("status = %d, want %d; body=%s", recorder.Code, tc.wantStatus, recorder.Body.String())
				}
				if tc.executed {
					if len(executor.calls) != 1 || executor.calls[0] != authB.ID {
						t.Fatalf("executor calls = %v, want only %s", executor.calls, authB.ID)
					}
				} else if len(executor.calls) != 0 {
					t.Fatalf("executor calls = %v, want none", executor.calls)
				}
				if tc.wantStatus != http.StatusConflict {
					if strings.Contains(recorder.Body.String(), "muse_account_unavailable") {
						t.Fatalf("passthrough body was rewritten: %s", recorder.Body.String())
					}
					return
				}
				var shape struct {
					Error struct {
						Code     string `json:"code"`
						Message  string `json:"message"`
						Metadata struct {
							Reason         string `json:"reason"`
							UpstreamStatus int    `json:"upstream_status"`
						} `json:"metadata"`
					} `json:"error"`
				}
				if err := json.Unmarshal(recorder.Body.Bytes(), &shape); err != nil {
					t.Fatalf("body is not JSON: %v: %s", err, recorder.Body.String())
				}
				if shape.Error.Code != "muse_account_unavailable" || shape.Error.Metadata.Reason != tc.reason {
					t.Fatalf("error = %+v, want code muse_account_unavailable reason %s", shape.Error, tc.reason)
				}
				if strings.Contains(recorder.Body.String(), "Billing verification failed") {
					t.Fatalf("409 body leaks upstream text: %s", recorder.Body.String())
				}
				if tc.executed {
					if shape.Error.Metadata.UpstreamStatus != tc.upstream {
						t.Fatalf("upstream_status = %d, want %d", shape.Error.Metadata.UpstreamStatus, tc.upstream)
					}
					if got := recorder.Header().Get(logging.MuseAccountHeader); got != authB.Index {
						t.Fatalf("%s = %q, want %q", logging.MuseAccountHeader, got, authB.Index)
					}
					traceID := recorder.Header().Get(logging.CPATraceIDHeader)
					if len(traceID) < 15 || !strings.HasPrefix(traceID[15:], authB.Index+"-") {
						t.Fatalf("trace ID = %q, want embedded index %q", traceID, authB.Index)
					}
					return
				}
				if _, ok := recorder.Header()[logging.MuseAccountHeader]; ok {
					t.Fatalf("%s = %q, want absent", logging.MuseAccountHeader, recorder.Header().Get(logging.MuseAccountHeader))
				}
				if got := recorder.Header().Get(logging.CPATraceIDHeader); got != "" {
					t.Fatalf("trace ID = %q, want absent", got)
				}
			})
		}
	}
}

// musePinChunkExecutor streams a fixed chunk script and records the auth IDs it saw.
type musePinChunkExecutor struct {
	musePinFailingExecutor
	chunks []cliproxyexecutor.StreamChunk
}

func (e *musePinChunkExecutor) ExecuteStream(_ context.Context, auth *cliproxyauth.Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.record(auth)
	ch := make(chan cliproxyexecutor.StreamChunk, len(e.chunks))
	for _, chunk := range e.chunks {
		ch <- chunk
	}
	close(ch)
	return &cliproxyexecutor.StreamResult{Chunks: ch}, nil
}

type musePinScopedErr struct{ musePinStatusErr }

func (e *musePinScopedErr) IsCredentialScoped() bool { return true }

func musePinServeStream(t *testing.T, executor cliproxyauth.ProviderExecutor, header func(a, b *cliproxyauth.Auth) string) (*httptest.ResponseRecorder, *cliproxyauth.Auth) {
	t.Helper()
	manager := cliproxyauth.NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	prefix := strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	var auths []*cliproxyauth.Auth
	for _, suffix := range []string{"-a", "-b"} {
		auth := &cliproxyauth.Auth{ID: prefix + suffix, Provider: "codex", Status: cliproxyauth.StatusActive, Metadata: map[string]any{"email": prefix + suffix}}
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: musePinWireModel}})
		id := auth.ID
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
		auth.EnsureIndex()
		auths = append(auths, auth)
	}
	h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager))
	router := gin.New()
	router.Use(logging.GinLogrusLogger(), logging.CPATraceIDMiddleware())
	router.POST("/v1/responses", h.Responses)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"`+musePinWireModel+`","input":"hello","stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(logging.MuseAccountHeader, header(auths[0], auths[1]))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder, auths[1]
}

// A chunk error that follows a non-data SSE line (no data frame written yet) must still become the
// fixed 409 body as an initial HTTP error, never a 401 carrying upstream text.
func TestResponsesMuseAccountPinStreamErrorAfterComment(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name     string
		err      error
		reason   string
		upstream int
	}{
		{name: "401", err: &musePinStatusErr{status: 401}, reason: "unauthorized", upstream: 401},
		{name: "402", err: &musePinStatusErr{status: 402}, reason: "payment_required", upstream: 402},
		{name: "quota_429", err: &musePinScopedErr{musePinStatusErr{status: 429}}, reason: "quota_exhausted", upstream: 429},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			executor := &musePinChunkExecutor{chunks: []cliproxyexecutor.StreamChunk{
				{Payload: []byte(": ping\n\n")},
				{Err: tc.err},
			}}
			recorder, authB := musePinServeStream(t, executor, func(_, b *cliproxyauth.Auth) string { return b.Index })

			body := recorder.Body.String()
			if recorder.Code == http.StatusUnauthorized {
				t.Fatalf("status must never be 401; body=%s", body)
			}
			if recorder.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body=%s", recorder.Code, body)
			}
			var shape struct {
				Error struct {
					Code     string `json:"code"`
					Metadata struct {
						Reason         string `json:"reason"`
						UpstreamStatus int    `json:"upstream_status"`
					} `json:"metadata"`
				} `json:"error"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &shape); err != nil {
				t.Fatalf("body is not JSON: %v: %s", err, body)
			}
			if shape.Error.Code != "muse_account_unavailable" || shape.Error.Metadata.Reason != tc.reason || shape.Error.Metadata.UpstreamStatus != tc.upstream {
				t.Fatalf("error = %+v, want muse_account_unavailable/%s/%d", shape.Error, tc.reason, tc.upstream)
			}
			if strings.Contains(body, "Billing verification failed") {
				t.Fatalf("body leaks upstream text: %s", body)
			}
			if len(executor.calls) != 1 || executor.calls[0] != authB.ID {
				t.Fatalf("executor calls = %v, want only %s", executor.calls, authB.ID)
			}
			if got := recorder.Header().Get(logging.MuseAccountHeader); got != authB.Index {
				t.Fatalf("%s = %q, want %q", logging.MuseAccountHeader, got, authB.Index)
			}
		})
	}
}

// After a real data frame the HTTP status is already 200, so the account-level error must be emitted as an
// SSE error event carrying the fixed 409 JSON instead of upstream text.
func TestResponsesMuseAccountPinStreamErrorAfterDataFrame(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &musePinChunkExecutor{chunks: []cliproxyexecutor.StreamChunk{
		{Payload: []byte("data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\"}}\n\n")},
		{Err: &musePinStatusErr{status: 401}},
	}}
	recorder, authB := musePinServeStream(t, executor, func(_, b *cliproxyauth.Auth) string { return b.Index })

	body := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (stream already started); body=%s", recorder.Code, body)
	}
	if !strings.Contains(body, "muse_account_unavailable") {
		t.Fatalf("SSE body lacks the muse error event: %s", body)
	}
	if strings.Contains(body, "Billing verification failed") {
		t.Fatalf("SSE body leaks upstream text: %s", body)
	}
	if len(executor.calls) != 1 || executor.calls[0] != authB.ID {
		t.Fatalf("executor calls = %v, want only %s", executor.calls, authB.ID)
	}
}
