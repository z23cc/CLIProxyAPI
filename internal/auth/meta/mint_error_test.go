package meta

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func newMintTestAuth(server *httptest.Server) *MetaAuth {
	auth := NewMetaAuth(&config.Config{})
	auth.httpClient = server.Client()
	auth.SetMintURL(server.URL + "/key")
	return auth
}

func TestMintAPIKey_NonSuccessReturnsMintError(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte("  \n{\"error\":\"x\"}\n  "))
			}))
			defer server.Close()

			resp, err := newMintTestAuth(server).MintAPIKey(context.Background(), "dca:token")
			if resp != nil {
				t.Fatalf("response = %+v, want nil", resp)
			}
			var mintErr *MintError
			if !errors.As(err, &mintErr) {
				t.Fatalf("error = %T %v, want *MintError", err, err)
			}
			if mintErr.StatusCode() != status {
				t.Fatalf("StatusCode() = %d, want %d", mintErr.StatusCode(), status)
			}
			if mintErr.Body != `{"error":"x"}` {
				t.Fatalf("Body = %q, want trimmed body", mintErr.Body)
			}
			want := fmt.Sprintf(`meta auth: mint key failed (HTTP %d): {"error":"x"}`, status)
			if err.Error() != want {
				t.Fatalf("Error() = %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestMintAPIKey_NetworkErrorIsNotMintError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	auth := newMintTestAuth(server)
	server.Close()

	_, err := auth.MintAPIKey(context.Background(), "dca:token")
	if err == nil {
		t.Fatal("expected network error")
	}
	var mintErr *MintError
	if errors.As(err, &mintErr) {
		t.Fatalf("network error must not be *MintError, got %v", err)
	}
}

func TestMintAPIKey_SuccessReturnsNoError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"api_key":"k","base_url":"https://x"}`))
	}))
	defer server.Close()

	resp, err := newMintTestAuth(server).MintAPIKey(context.Background(), "dca:token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.APIKey != "k" {
		t.Fatalf("response = %+v, want api_key k", resp)
	}
}
