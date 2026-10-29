package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

const (
	museTestModel      = "muse-pin-model"
	museTestOtherModel = "muse-pin-other-model"
	museUpstreamText   = "Billing verification failed Permission denied"
)

// museStatusErr mimics executor status errors: StatusCode plus optional credential scope and retry hint.
type museStatusErr struct {
	status int
	scoped bool
	retry  *time.Duration
}

func (e *museStatusErr) Error() string              { return museUpstreamText }
func (e *museStatusErr) StatusCode() int            { return e.status }
func (e *museStatusErr) IsCredentialScoped() bool   { return e.scoped }
func (e *museStatusErr) RetryAfter() *time.Duration { return e.retry }

// museFakeExecutor fails per auth ID with a configured error and records every call.
type museFakeExecutor struct {
	id string

	mu      sync.Mutex
	calls   []string
	errs    map[string]error // authID -> error for Execute / ExecuteStream / CountTokens
	afterFn map[string]error // authID -> error delivered after the first stream payload

	clearAfterFirst bool
}

func (e *museFakeExecutor) Identifier() string {
	if e.id != "" {
		return e.id
	}
	return "codex"
}

func (e *museFakeExecutor) record(auth *coreauth.Auth) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, auth.ID)
	if e.clearAfterFirst && len(e.calls) > 1 {
		return nil
	}
	return e.errs[auth.ID]
}

func (e *museFakeExecutor) Calls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.calls...)
}

func (e *museFakeExecutor) setErr(authID string, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.errs == nil {
		e.errs = map[string]error{}
	}
	e.errs[authID] = err
}

// clearErrAfterFirstCall makes every auth succeed once the first call has been recorded.
func (e *museFakeExecutor) clearErrAfterFirstCall() { e.clearAfterFirst = true }

func (e *museFakeExecutor) Execute(_ context.Context, auth *coreauth.Auth, _ coreexecutor.Request, _ coreexecutor.Options) (coreexecutor.Response, error) {
	if err := e.record(auth); err != nil {
		return coreexecutor.Response{}, err
	}
	return coreexecutor.Response{Payload: []byte("ok")}, nil
}

func (e *museFakeExecutor) ExecuteStream(_ context.Context, auth *coreauth.Auth, _ coreexecutor.Request, _ coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	err := e.record(auth)
	e.mu.Lock()
	after := e.afterFn[auth.ID]
	e.mu.Unlock()
	ch := make(chan coreexecutor.StreamChunk, 2)
	switch {
	case after != nil:
		ch <- coreexecutor.StreamChunk{Payload: []byte("first")}
		ch <- coreexecutor.StreamChunk{Err: after}
	case err != nil:
		// Bootstrap failure: the error is the first chunk, before any payload.
		ch <- coreexecutor.StreamChunk{Err: err}
	default:
		ch <- coreexecutor.StreamChunk{Payload: []byte("ok")}
	}
	close(ch)
	return &coreexecutor.StreamResult{Chunks: ch}, nil
}

func (e *museFakeExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	return auth, nil
}

func (e *museFakeExecutor) CountTokens(_ context.Context, auth *coreauth.Auth, _ coreexecutor.Request, _ coreexecutor.Options) (coreexecutor.Response, error) {
	if err := e.record(auth); err != nil {
		return coreexecutor.Response{}, err
	}
	return coreexecutor.Response{Payload: []byte("ok")}, nil
}

func (e *museFakeExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, &coreauth.Error{Code: "not_implemented", Message: "HttpRequest not implemented", HTTPStatus: http.StatusNotImplemented}
}

type museEnv struct {
	handler  *BaseAPIHandler
	manager  *coreauth.Manager
	executor *museFakeExecutor
	authA    *coreauth.Auth // supports museTestModel and museTestOtherModel
	authB    *coreauth.Auth // supports museTestModel only
	authC    *coreauth.Auth // other provider
}

func museRegisterAuth(t *testing.T, manager *coreauth.Manager, id, provider string, models ...string) *coreauth.Auth {
	t.Helper()
	auth := &coreauth.Auth{ID: id, Provider: provider, Status: coreauth.StatusActive, Metadata: map[string]any{"email": id + "@example.com"}}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("manager.Register(%s): %v", id, err)
	}
	infos := make([]*registry.ModelInfo, 0, len(models))
	for _, model := range models {
		infos = append(infos, &registry.ModelInfo{ID: model})
	}
	registry.GetGlobalRegistry().RegisterClient(id, provider, infos)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	auth.EnsureIndex()
	return auth
}

func newMuseEnv(t *testing.T, affinity bool) *museEnv {
	t.Helper()
	var selector coreauth.Selector
	if affinity {
		selector = coreauth.NewSessionAffinitySelector(nil)
	}
	manager := coreauth.NewManager(nil, selector, nil)
	executor := &museFakeExecutor{}
	manager.RegisterExecutor(executor)
	manager.RegisterExecutor(&museFakeExecutor{id: "muse-other"})
	prefix := strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	env := &museEnv{
		manager:  manager,
		executor: executor,
		authA:    museRegisterAuth(t, manager, prefix+"-a", "codex", museTestModel, museTestOtherModel),
		authB:    museRegisterAuth(t, manager, prefix+"-b", "codex", museTestModel),
		authC:    museRegisterAuth(t, manager, prefix+"-c", "muse-other", museTestModel+"-c"),
	}
	env.handler = NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager)
	return env
}

func museAffinityModes(t *testing.T, run func(t *testing.T, affinity bool)) {
	t.Helper()
	for _, affinity := range []bool{false, true} {
		name := "affinity_off"
		if affinity {
			name = "affinity_on"
		}
		t.Run(name, func(t *testing.T) { run(t, affinity) })
	}
}

type museResult struct {
	rec     *httptest.ResponseRecorder
	payload string
}

// museServe runs fn on a gin context carrying the X-Muse-Account request header and renders the result
// with the real error writer, behind CPATraceIDMiddleware like the server.
func museServe(t *testing.T, header string, fn func(ctx context.Context, h *gin.Context) ([]byte, *interfaces.ErrorMessage), env *museEnv) museResult {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(logging.CPATraceIDMiddleware())
	var payload string
	engine.POST("/v1/responses", func(c *gin.Context) {
		logging.SetGinRequestID(c, "1234abcd")
		ctx := context.WithValue(context.Background(), "gin", c)
		out, errMsg := fn(ctx, c)
		if errMsg != nil {
			env.handler.WriteErrorResponse(c, errMsg)
			return
		}
		payload = string(out)
		_, _ = c.Writer.Write(out)
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	if header != "" {
		req.Header.Set(logging.MuseAccountHeader, header)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return museResult{rec: rec, payload: payload}
}

var museBody = []byte(`{"model":"` + museTestModel + `"}`)

func (env *museEnv) doExecute(t *testing.T, header string, model string) museResult {
	return museServe(t, header, func(ctx context.Context, _ *gin.Context) ([]byte, *interfaces.ErrorMessage) {
		out, _, errMsg := env.handler.ExecuteWithAuthManager(ctx, "openai", model, []byte(`{"model":"`+model+`"}`), "")
		return out, errMsg
	}, env)
}

func (env *museEnv) doCount(t *testing.T, header string) museResult {
	return museServe(t, header, func(ctx context.Context, _ *gin.Context) ([]byte, *interfaces.ErrorMessage) {
		out, _, errMsg := env.handler.ExecuteCountWithAuthManager(ctx, "openai", museTestModel, museBody, "")
		return out, errMsg
	}, env)
}

func (env *museEnv) doStream(t *testing.T, header string, model string) museResult {
	return museServe(t, header, func(ctx context.Context, _ *gin.Context) ([]byte, *interfaces.ErrorMessage) {
		dataChan, _, errChan := env.handler.ExecuteStreamWithAuthManager(ctx, "openai", model, []byte(`{"model":"`+model+`"}`), "")
		var out []byte
		// Early failures return a nil data channel; ranging over it would block forever.
		if dataChan != nil {
			for chunk := range dataChan {
				out = append(out, chunk...)
			}
		}
		var firstErr *interfaces.ErrorMessage
		for msg := range errChan {
			if msg != nil && firstErr == nil {
				firstErr = msg
			}
		}
		return out, firstErr
	}, env)
}

type museBodyShape struct {
	Error struct {
		Type     string `json:"type"`
		Code     string `json:"code"`
		Message  string `json:"message"`
		Metadata struct {
			Reason            string `json:"reason"`
			UpstreamStatus    int    `json:"upstream_status"`
			RetryAfterSeconds int    `json:"retry_after_seconds"`
		} `json:"metadata"`
	} `json:"error"`
}

// requireMuse409 asserts the response is the fixed-template 409 and returns the parsed body.
func requireMuse409(t *testing.T, res museResult, reason string, upstreamStatus int) museBodyShape {
	t.Helper()
	body := res.rec.Body.String()
	if res.rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", res.rec.Code, body)
	}
	if !json.Valid([]byte(body)) {
		t.Fatalf("body is not valid JSON: %s", body)
	}
	var shape museBodyShape
	if err := json.Unmarshal([]byte(body), &shape); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if shape.Error.Code != "muse_account_unavailable" || shape.Error.Type != "invalid_request_error" {
		t.Fatalf("error = %+v, want muse_account_unavailable/invalid_request_error", shape.Error)
	}
	if shape.Error.Metadata.Reason != reason {
		t.Fatalf("reason = %q, want %q; body=%s", shape.Error.Metadata.Reason, reason, body)
	}
	if shape.Error.Metadata.UpstreamStatus != upstreamStatus {
		t.Fatalf("upstream_status = %d, want %d", shape.Error.Metadata.UpstreamStatus, upstreamStatus)
	}
	for _, leak := range []string{"Billing verification failed", "Permission denied"} {
		if strings.Contains(body, leak) {
			t.Fatalf("409 body leaks upstream text %q: %s", leak, body)
		}
	}
	return shape
}

func requireNoMuseHeaders(t *testing.T, res museResult) {
	t.Helper()
	if _, ok := res.rec.Header()[logging.MuseAccountHeader]; ok {
		t.Fatalf("%s = %q, want absent", logging.MuseAccountHeader, res.rec.Header().Get(logging.MuseAccountHeader))
	}
	if got := res.rec.Header().Get(logging.CPATraceIDHeader); got != "" {
		t.Fatalf("trace ID = %q, want absent", got)
	}
}

func requireCalls(t *testing.T, executor *museFakeExecutor, want ...string) {
	t.Helper()
	got := executor.Calls()
	if len(got) != len(want) {
		t.Fatalf("executor calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("executor calls = %v, want %v", got, want)
		}
	}
}

func TestMuseAccountPinHonoredOnSuccess(t *testing.T) {
	museAffinityModes(t, func(t *testing.T, affinity bool) {
		for _, path := range []string{"execute", "stream", "count"} {
			t.Run(path, func(t *testing.T) {
				env := newMuseEnv(t, affinity)
				// Repeat so a round-robin selector would reach auth A at least once if the pin were ignored.
				for range 4 {
					var res museResult
					switch path {
					case "execute":
						res = env.doExecute(t, env.authB.EnsureIndex(), museTestModel)
					case "stream":
						res = env.doStream(t, env.authB.EnsureIndex(), museTestModel)
					default:
						res = env.doCount(t, env.authB.EnsureIndex())
					}
					if res.rec.Code != http.StatusOK {
						t.Fatalf("status = %d, body=%s", res.rec.Code, res.rec.Body.String())
					}
					// Execute, stream and count all publish the selected auth into the trace state.
					if got := res.rec.Header().Get(logging.MuseAccountHeader); got != env.authB.Index {
						t.Fatalf("%s = %q, want %q", logging.MuseAccountHeader, got, env.authB.Index)
					}
				}
				for _, id := range env.executor.Calls() {
					if id != env.authB.ID {
						t.Fatalf("executor calls = %v, want only %s", env.executor.Calls(), env.authB.ID)
					}
				}
				if len(env.executor.Calls()) != 4 {
					t.Fatalf("executor calls = %v, want 4", env.executor.Calls())
				}
			})
		}
	})
}

func TestMuseAccountPinHeaderIsTrimmedAndCaseInsensitive(t *testing.T) {
	env := newMuseEnv(t, false)
	res := env.doExecute(t, "  "+strings.ToUpper(env.authB.EnsureIndex())+" ", museTestModel)
	if res.rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", res.rec.Code, res.rec.Body.String())
	}
	requireCalls(t, env.executor, env.authB.ID)
}

func TestMuseAccountPinSelectionStage409(t *testing.T) {
	cases := []struct {
		name   string
		header func(env *museEnv) string
		setup  func(env *museEnv)
		model  string
		reason string
		// echo is the index the message must contain.
		echo func(env *museEnv) string
	}{
		{name: "unknown_index", header: func(*museEnv) string { return "deadbeefdeadbeef" }, model: museTestModel, reason: "not_found", echo: func(*museEnv) string { return "deadbeefdeadbeef" }},
		{name: "garbage_header", header: func(*museEnv) string { return "Billing verification failed" }, model: museTestModel, reason: "not_found", echo: func(*museEnv) string { return "invalid" }},
		{name: "disabled_auth", header: func(env *museEnv) string { return env.authB.Index }, model: museTestModel, reason: "disabled", echo: func(env *museEnv) string { return env.authB.Index },
			setup: func(env *museEnv) {
				disabled := env.authB.Clone()
				disabled.Disabled = true
				disabled.Status = coreauth.StatusDisabled
				if _, err := env.manager.Update(context.Background(), disabled); err != nil {
					panic(err)
				}
			}},
		{name: "other_provider", header: func(env *museEnv) string { return env.authC.Index }, model: museTestModel, reason: "model_unsupported", echo: func(env *museEnv) string { return env.authC.Index }},
		{name: "model_not_supported", header: func(env *museEnv) string { return env.authB.Index }, model: museTestOtherModel, reason: "model_unsupported", echo: func(env *museEnv) string { return env.authB.Index }},
	}
	museAffinityModes(t, func(t *testing.T, affinity bool) {
		for _, tc := range cases {
			for _, path := range []string{"execute", "stream", "count"} {
				t.Run(tc.name+"/"+path, func(t *testing.T) {
					env := newMuseEnv(t, affinity)
					if tc.setup != nil {
						tc.setup(env)
					}
					var res museResult
					switch path {
					case "execute":
						res = env.doExecute(t, tc.header(env), tc.model)
					case "stream":
						res = env.doStream(t, tc.header(env), tc.model)
					default:
						if tc.model != museTestModel {
							t.Skip("count helper uses the default model")
						}
						res = env.doCount(t, tc.header(env))
					}
					shape := requireMuse409(t, res, tc.reason, 0)
					if want := "muse account " + tc.echo(env) + " is unavailable (" + tc.reason + ")"; shape.Error.Message != want {
						t.Fatalf("message = %q, want %q", shape.Error.Message, want)
					}
					if res.rec.Code == http.StatusUnauthorized {
						t.Fatal("status must never be 401")
					}
					requireNoMuseHeaders(t, res)
					requireCalls(t, env.executor)
				})
			}
		}
	})
}

func TestMuseAccountPinCooldownRealFlow(t *testing.T) {
	museAffinityModes(t, func(t *testing.T, affinity bool) {
		for _, path := range []string{"execute", "stream"} {
			t.Run(path, func(t *testing.T) {
				env := newMuseEnv(t, affinity)
				env.executor.setErr(env.authB.ID, &museStatusErr{status: http.StatusTooManyRequests})
				run := func() museResult {
					if path == "stream" {
						return env.doStream(t, env.authB.Index, museTestModel)
					}
					return env.doExecute(t, env.authB.Index, museTestModel)
				}

				first := run()
				if first.rec.Code != http.StatusTooManyRequests {
					t.Fatalf("first status = %d, want passthrough 429; body=%s", first.rec.Code, first.rec.Body.String())
				}
				if strings.Contains(first.rec.Body.String(), "muse_account_unavailable") {
					t.Fatalf("plain 429 must not be rewritten: %s", first.rec.Body.String())
				}
				requireCalls(t, env.executor, env.authB.ID)

				second := run()
				shape := requireMuse409(t, second, "cooling_down", 0)
				if shape.Error.Metadata.RetryAfterSeconds <= 0 {
					t.Fatalf("retry_after_seconds = %d, want > 0", shape.Error.Metadata.RetryAfterSeconds)
				}
				requireCalls(t, env.executor, env.authB.ID)
			})
		}
	})
}

// A cooldown error must never be classified as model_unsupported, even when the request model does not
// match the key of the auth's model state.
func TestMuseAccountPinCooldownErrorIsNeverModelUnsupported(t *testing.T) {
	env := newMuseEnv(t, false)
	pin := &museAccountPin{index: env.authB.Index, authID: env.authB.ID, manager: env.manager}
	msg := pin.errorMessage(coreauth.NewModelCooldownError("some-other-model", "codex", 30*time.Second), museTestModel)
	if msg.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", msg.StatusCode)
	}
	var shape museBodyShape
	if err := json.Unmarshal([]byte(msg.Error.Error()), &shape); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if shape.Error.Metadata.Reason != "cooling_down" {
		t.Fatalf("reason = %q, want cooling_down", shape.Error.Metadata.Reason)
	}
	if shape.Error.Metadata.UpstreamStatus != 0 {
		t.Fatalf("upstream_status = %d, want 0", shape.Error.Metadata.UpstreamStatus)
	}
}

func TestMuseAccountPinUpstreamErrorMapping(t *testing.T) {
	retry := 120 * time.Second
	cases := []struct {
		name       string
		err        error
		wantStatus int // 409 for rewrites, original status for passthrough
		reason     string
		upstream   int
		retryAfter int
	}{
		{name: "401", err: &museStatusErr{status: 401}, wantStatus: 409, reason: "unauthorized", upstream: 401},
		{name: "402", err: &museStatusErr{status: 402}, wantStatus: 409, reason: "payment_required", upstream: 402},
		{name: "403", err: &museStatusErr{status: 403}, wantStatus: 409, reason: "forbidden", upstream: 403},
		{name: "404", err: &museStatusErr{status: 404}, wantStatus: 409, reason: "model_unavailable", upstream: 404},
		{name: "quota_429", err: &museStatusErr{status: 429, scoped: true, retry: &retry}, wantStatus: 409, reason: "quota_exhausted", upstream: 429, retryAfter: 120},
		{name: "plain_429", err: &museStatusErr{status: 429}, wantStatus: 429},
		{name: "503", err: &museStatusErr{status: 503}, wantStatus: 503},
		{name: "400", err: &museStatusErr{status: 400}, wantStatus: 400},
	}
	museAffinityModes(t, func(t *testing.T, affinity bool) {
		for _, tc := range cases {
			for _, path := range []string{"execute", "stream", "count"} {
				t.Run(tc.name+"/"+path, func(t *testing.T) {
					env := newMuseEnv(t, affinity)
					env.executor.setErr(env.authB.ID, tc.err)
					var res museResult
					switch path {
					case "execute":
						res = env.doExecute(t, env.authB.Index, museTestModel)
					case "stream":
						res = env.doStream(t, env.authB.Index, museTestModel)
					default:
						res = env.doCount(t, env.authB.Index)
					}
					if res.rec.Code == http.StatusUnauthorized {
						t.Fatal("status must never be 401")
					}
					requireCalls(t, env.executor, env.authB.ID) // exactly one call, no failover to auth A
					if tc.wantStatus == http.StatusConflict {
						shape := requireMuse409(t, res, tc.reason, tc.upstream)
						if shape.Error.Metadata.RetryAfterSeconds != tc.retryAfter {
							t.Fatalf("retry_after_seconds = %d, want %d", shape.Error.Metadata.RetryAfterSeconds, tc.retryAfter)
						}
						if got := res.rec.Header().Get(logging.MuseAccountHeader); got != env.authB.Index {
							t.Fatalf("%s = %q, want pinned auth %q", logging.MuseAccountHeader, got, env.authB.Index)
						}
						return
					}
					if res.rec.Code != tc.wantStatus {
						t.Fatalf("status = %d, want passthrough %d; body=%s", res.rec.Code, tc.wantStatus, res.rec.Body.String())
					}
					if strings.Contains(res.rec.Body.String(), "muse_account_unavailable") {
						t.Fatalf("passthrough body was rewritten: %s", res.rec.Body.String())
					}
				})
			}
		}
	})
}

func TestMuseAccountPinStreamErrorAfterFirstChunk(t *testing.T) {
	t.Run("account level error is rewritten", func(t *testing.T) {
		env := newMuseEnv(t, false)
		env.executor.afterFn = map[string]error{env.authB.ID: &museStatusErr{status: 402}}
		res := env.doStream(t, env.authB.Index, museTestModel)
		requireMuse409(t, res, "payment_required", 402)
		requireCalls(t, env.executor, env.authB.ID)
	})
	t.Run("server error passes through", func(t *testing.T) {
		env := newMuseEnv(t, false)
		env.executor.afterFn = map[string]error{env.authB.ID: &museStatusErr{status: 503}}
		res := env.doStream(t, env.authB.Index, museTestModel)
		if res.rec.Code != http.StatusServiceUnavailable || strings.Contains(res.rec.Body.String(), "muse_account_unavailable") {
			t.Fatalf("503 chunk error was rewritten: status=%d body=%s", res.rec.Code, res.rec.Body.String())
		}
		requireCalls(t, env.executor, env.authB.ID)
	})
}

// newMuseRetryEnv is newMuseEnv with Streaming.BootstrapRetries = 1.
func newMuseRetryEnv(t *testing.T, affinity bool) *museEnv {
	t.Helper()
	env := newMuseEnv(t, affinity)
	env.handler = NewBaseAPIHandlers(&sdkconfig.SDKConfig{Streaming: sdkconfig.StreamingConfig{BootstrapRetries: 1}}, env.manager)
	return env
}

func TestMuseAccountPinBootstrapRetryKeepsFirstError(t *testing.T) {
	museAffinityModes(t, func(t *testing.T, affinity bool) {
		t.Run("plain 429 stays 429", func(t *testing.T) {
			env := newMuseRetryEnv(t, affinity)
			env.executor.setErr(env.authB.ID, &museStatusErr{status: http.StatusTooManyRequests})
			res := env.doStream(t, env.authB.Index, museTestModel)
			if res.rec.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want passthrough 429; body=%s", res.rec.Code, res.rec.Body.String())
			}
			if strings.Contains(res.rec.Body.String(), "muse_account_unavailable") {
				t.Fatalf("plain 429 was rewritten: %s", res.rec.Body.String())
			}
			requireCalls(t, env.executor, env.authB.ID)
		})
		t.Run("401 is unauthorized not cooling_down", func(t *testing.T) {
			env := newMuseRetryEnv(t, affinity)
			env.executor.setErr(env.authB.ID, &museStatusErr{status: http.StatusUnauthorized})
			res := env.doStream(t, env.authB.Index, museTestModel)
			requireMuse409(t, res, "unauthorized", 401)
			for _, id := range env.executor.Calls() {
				if id != env.authB.ID {
					t.Fatalf("executor calls = %v, want only pinned auth %s", env.executor.Calls(), env.authB.ID)
				}
			}
		})
		t.Run("unpinned request still fails over", func(t *testing.T) {
			env := newMuseRetryEnv(t, affinity)
			env.executor.setErr(env.authA.ID, &museStatusErr{status: http.StatusTooManyRequests})
			env.executor.setErr(env.authB.ID, &museStatusErr{status: http.StatusTooManyRequests})
			// Whichever auth is picked first fails; clearing the other lets the bootstrap retry succeed there.
			env.executor.clearErrAfterFirstCall()
			res := env.doStream(t, "", museTestModel)
			if res.rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 after failover; body=%s", res.rec.Code, res.rec.Body.String())
			}
			calls := env.executor.Calls()
			if len(calls) != 2 || calls[0] == calls[1] {
				t.Fatalf("executor calls = %v, want two distinct auths", calls)
			}
		})
	})
}

func TestMuseAccountPinPrecedence(t *testing.T) {
	t.Run("explicit pin wins over header", func(t *testing.T) {
		env := newMuseEnv(t, false)
		res := museServe(t, env.authB.Index, func(ctx context.Context, _ *gin.Context) ([]byte, *interfaces.ErrorMessage) {
			ctx = WithPinnedAuthID(ctx, env.authA.ID)
			out, _, errMsg := env.handler.ExecuteWithAuthManager(ctx, "openai", museTestModel, museBody, "")
			return out, errMsg
		}, env)
		if res.rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", res.rec.Code, res.rec.Body.String())
		}
		requireCalls(t, env.executor, env.authA.ID)
	})

	t.Run("internal execution ignores header", func(t *testing.T) {
		env := newMuseEnv(t, false)
		res := museServe(t, "deadbeefdeadbeef", func(ctx context.Context, _ *gin.Context) ([]byte, *interfaces.ErrorMessage) {
			resp, errMsg := env.handler.ExecuteModel(ctx, ModelExecutionRequest{EntryProtocol: "openai", ExitProtocol: "openai", Model: museTestModel, Body: museBody})
			return resp.Body, errMsg
		}, env)
		if res.rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", res.rec.Code, res.rec.Body.String())
		}
		if len(env.executor.Calls()) != 1 {
			t.Fatalf("executor calls = %v, want 1", env.executor.Calls())
		}
	})

	t.Run("internal execution is not pinned by header", func(t *testing.T) {
		env := newMuseEnv(t, false)
		// Header names a valid auth; the internal call must still be free to pick any auth.
		seen := map[string]bool{}
		for range 4 {
			museServe(t, env.authB.Index, func(ctx context.Context, _ *gin.Context) ([]byte, *interfaces.ErrorMessage) {
				resp, errMsg := env.handler.ExecuteModel(ctx, ModelExecutionRequest{EntryProtocol: "openai", ExitProtocol: "openai", Model: museTestModel, Body: museBody})
				return resp.Body, errMsg
			}, env)
		}
		for _, id := range env.executor.Calls() {
			seen[id] = true
		}
		if !seen[env.authA.ID] || !seen[env.authB.ID] {
			t.Fatalf("internal executions should round-robin over both auths, got %v", env.executor.Calls())
		}
	})

	t.Run("no header is unchanged", func(t *testing.T) {
		env := newMuseEnv(t, false)
		res := env.doExecute(t, "", museTestModel)
		if res.rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", res.rec.Code, res.rec.Body.String())
		}
	})

	t.Run("no header does not pin or rewrite", func(t *testing.T) {
		env := newMuseEnv(t, false)
		env.executor.setErr(env.authA.ID, &museStatusErr{status: 402})
		env.executor.setErr(env.authB.ID, &museStatusErr{status: 402})
		res := env.doExecute(t, "", museTestModel)
		if res.rec.Code == http.StatusConflict || strings.Contains(res.rec.Body.String(), "muse_account_unavailable") {
			t.Fatalf("unheadered request was rewritten: status=%d body=%s", res.rec.Code, res.rec.Body.String())
		}
	})
}
