package openai

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	_ "github.com/router-for-me/CLIProxyAPI/v8/internal/translator"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

// TestResponsesMuseAccountHeader drives /v1/responses through the real Antigravity executor against a
// fake SSE upstream, with the same middleware order as the server (GinLogrusLogger -> CPATraceIDMiddleware).
func TestResponsesMuseAccountHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, stream := range []bool{false, true} {
		name := "non_stream"
		body := `{"model":"gemini-3.7-flash","input":"hello","stream":false}`
		if stream {
			name = "stream"
			body = `{"model":"gemini-3.7-flash","input":"hello","stream":true}`
		}
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, `data: {"response":{"candidates":[{"content":{"role":"model","parts":[{"text":"hello"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":2,"totalTokenCount":3},"responseId":"resp-test"}}`+"\n\n")
			}))
			defer server.Close()

			manager := cliproxyauth.NewManager(nil, nil, nil)
			manager.RegisterExecutor(runtimeexecutor.NewAntigravityExecutor(&config.Config{}))
			auth := &cliproxyauth.Auth{
				ID: t.Name(), Provider: "antigravity", Status: cliproxyauth.StatusActive, ProxyURL: "direct",
				Metadata:   map[string]any{"access_token": "token", "expired": time.Now().Add(time.Hour).Format(time.RFC3339), "project_id": "project"},
				Attributes: map[string]string{"base_url": server.URL},
			}
			if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
				t.Fatal(errRegister)
			}
			registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "gemini-3.7-flash"}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })

			h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager))
			router := gin.New()
			router.Use(logging.GinLogrusLogger(), logging.CPATraceIDMiddleware())
			router.POST("/v1/responses", h.Responses)

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body)))

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
			want := auth.EnsureIndex()
			if want == "" {
				t.Fatal("auth index is empty")
			}
			if got := recorder.Header().Get(logging.MuseAccountHeader); got != want {
				t.Fatalf("%s = %q, want %q", logging.MuseAccountHeader, got, want)
			}
			// Trace ID is <timestamp>-<authIndex>-<requestID>; the request ID is a UUID containing dashes.
			traceID := recorder.Header().Get(logging.CPATraceIDHeader)
			if len(traceID) < 15 || !strings.HasPrefix(traceID[15:], want+"-") {
				t.Fatalf("trace ID = %q, want middle segment %q", traceID, want)
			}
		})
	}
}
