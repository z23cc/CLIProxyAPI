package auth

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	metaauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/meta"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestManager_Execute_MetaMintErrorClassifiesRefreshFailure(t *testing.T) {
	tests := []struct {
		name            string
		mintStatus      int
		wantStatusMsg   string
		wantTerminal401 bool
		wantNextRefresh bool
	}{
		{"mint 401 is terminal unauthorized", http.StatusUnauthorized, "unauthorized", true, false},
		// The generic refresh-failure branch sets "token expired" but the original 401
		// execution result is then recorded on the primary and overwrites the message
		// and LastError, so only the non-terminal state and the refresh backoff are asserted.
		{"mint 403 keeps generic backoff", http.StatusForbidden, "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := "meta-model"
			primary := &Auth{
				ID:       "aa-meta-primary",
				Provider: "meta",
				Metadata: map[string]any{"access_token": "stale-access-token", "dca_token": "dca:primary"},
			}
			backup := &Auth{
				ID:       "bb-meta-backup",
				Provider: "meta",
				Metadata: map[string]any{"access_token": "backup-access-token", "dca_token": "dca:backup"},
			}
			// Same shape the Meta executor produces when MintAPIKey fails.
			mintErr := fmt.Errorf("meta executor: mint API key failed: %w",
				&metaauth.MintError{Status: tt.mintStatus, Body: "mint rejected"})
			executor := &unauthorizedRefreshExecutor{
				id:           "meta",
				tokenInvalid: map[string]struct{}{"stale-access-token": {}},
				refreshErr:   mintErr,
			}

			m := NewManager(nil, nil, nil)
			m.RegisterExecutor(executor)
			reg := registry.GetGlobalRegistry()
			reg.RegisterClient(primary.ID, "meta", []*registry.ModelInfo{{ID: model}})
			reg.RegisterClient(backup.ID, "meta", []*registry.ModelInfo{{ID: model}})
			t.Cleanup(func() {
				reg.UnregisterClient(primary.ID)
				reg.UnregisterClient(backup.ID)
			})
			for _, a := range []*Auth{primary, backup} {
				if _, err := m.Register(context.Background(), a); err != nil {
					t.Fatalf("register %s: %v", a.ID, err)
				}
			}

			resp, err := m.Execute(context.Background(), []string{"meta"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
			if err != nil {
				t.Fatalf("Execute error = %v, want success via backup", err)
			}
			if got := string(resp.Payload); got != backup.ID+":backup-access-token" {
				t.Fatalf("payload = %q, want backup response", got)
			}
			if got := executor.RefreshCalls(); got != 1 {
				t.Fatalf("Refresh calls = %d, want 1", got)
			}

			updated, ok := m.GetByID(primary.ID)
			if !ok || updated == nil {
				t.Fatal("primary auth missing")
			}
			if tt.wantStatusMsg == "" && updated.StatusMessage == "unauthorized" {
				t.Fatalf("StatusMessage = %q, want non-terminal message", updated.StatusMessage)
			}
			if tt.wantStatusMsg != "" && updated.StatusMessage != tt.wantStatusMsg {
				t.Fatalf("StatusMessage = %q, want %q", updated.StatusMessage, tt.wantStatusMsg)
			}
			if !updated.Unavailable || updated.Status != StatusError {
				t.Fatalf("Unavailable=%v Status=%v, want unavailable error", updated.Unavailable, updated.Status)
			}
			if got := hasUnauthorizedAuthFailure(updated); got != tt.wantTerminal401 {
				t.Fatalf("hasUnauthorizedAuthFailure = %v, want %v", got, tt.wantTerminal401)
			}
			if got := !updated.NextRefreshAfter.IsZero(); got != tt.wantNextRefresh {
				t.Fatalf("NextRefreshAfter set = %v, want %v", got, tt.wantNextRefresh)
			}
		})
	}
}
