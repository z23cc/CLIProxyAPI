package management

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func metaADFieldsAuth(t *testing.T, metadata map[string]any) (*Handler, *coreauth.Auth) {
	t.Helper()
	t.Setenv("MANAGEMENT_PASSWORD", "")
	authDir := t.TempDir()
	fileName := "meta-user.json"
	path := filepath.Join(authDir, fileName)
	if errWrite := os.WriteFile(path, []byte(`{"type":"meta"}`), 0o600); errWrite != nil {
		t.Fatalf("write auth file: %v", errWrite)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, nil)
	auth := &coreauth.Auth{
		ID:         "meta-user",
		Index:      "idx-meta",
		FileName:   fileName,
		Provider:   "meta",
		Status:     coreauth.StatusDisabled,
		Disabled:   true,
		Attributes: map[string]string{"path": path},
		Metadata:   metadata,
	}
	return h, auth
}

func TestMetaAutoDisableFields_EntryExposesCoreMarkers(t *testing.T) {
	h, auth := metaADFieldsAuth(t, map[string]any{
		"disabled": true, "disabled_by": "cliproxyapi", "disabled_reason": "new_key_rejected", "disabled_at": "2026-10-28T10:00:00Z",
	})
	entry := h.buildAuthFileEntry(auth, authFileQuotaContext{})
	if entry["disabled_by"] != "cliproxyapi" || entry["disabled_reason"] != "new_key_rejected" || entry["disabled_at"] != "2026-10-28T10:00:00Z" {
		t.Fatalf("markers missing from the entry: %#v", entry)
	}
	if _, ok := entry["meta_auto_disable"]; ok {
		t.Fatalf("a disabled credential reported a running check: %#v", entry["meta_auto_disable"])
	}
}

func TestMetaAutoDisableFields_EntryOmitsAbsentAndForeignMarkers(t *testing.T) {
	for name, metadata := range map[string]map[string]any{
		"none":             {"disabled": true},
		"usage_statistics": {"disabled": true, "disabled_by": "usage-statistics", "disabled_reason": "mint_rejected"},
	} {
		t.Run(name, func(t *testing.T) {
			h, auth := metaADFieldsAuth(t, metadata)
			entry := h.buildAuthFileEntry(auth, authFileQuotaContext{})
			for _, key := range []string{"disabled_by", "disabled_reason", "disabled_at", "meta_auto_disable"} {
				if _, ok := entry[key]; ok {
					t.Fatalf("entry has %q: %#v", key, entry)
				}
			}
		})
	}
}

func TestMetaAutoDisableFields_EnableClearsCoreMarkersOnly(t *testing.T) {
	core := &coreauth.Auth{Provider: "meta", Disabled: true, Metadata: map[string]any{
		"disabled": true, "disabled_by": "cliproxyapi", "disabled_reason": "mint_rejected", "disabled_at": "2026-10-28T10:00:00Z",
	}}
	applyAuthDisabledState(core, false)
	for _, key := range []string{"disabled_by", "disabled_reason", "disabled_at"} {
		if _, ok := core.Metadata[key]; ok {
			t.Fatalf("enable kept marker %q: %#v", key, core.Metadata)
		}
	}
	if core.Disabled || core.Metadata["disabled"] != false {
		t.Fatalf("credential not enabled: %#v", core.Metadata)
	}

	foreign := &coreauth.Auth{Provider: "meta", Disabled: true, Metadata: map[string]any{
		"disabled": true, "disabled_by": "usage-statistics", "disabled_reason": "mint_rejected",
	}}
	applyAuthDisabledState(foreign, false)
	if foreign.Metadata["disabled_by"] != "usage-statistics" {
		t.Fatalf("enable touched another writer's marker: %#v", foreign.Metadata)
	}

	// U1: an admin explicitly disabling a core-marked credential takes it over, so a later
	// re-login keeps the disable instead of dropping it as a core auto-disable.
	adminTakeover := &coreauth.Auth{Provider: "meta", Disabled: true, Metadata: map[string]any{
		"disabled": true, "disabled_by": "cliproxyapi", "disabled_reason": "mint_rejected", "disabled_at": "2026-10-28T10:00:00Z",
	}}
	applyAuthDisabledState(adminTakeover, true)
	if _, ok := adminTakeover.Metadata["disabled_by"]; ok {
		t.Fatalf("explicit disable kept the core marker: %#v", adminTakeover.Metadata)
	}
	relogin := &coreauth.Auth{Provider: "meta", Metadata: map[string]any{"type": "meta", "access_token": "new-key"}}
	coreauth.MergeExistingAuthMetadata(relogin, adminTakeover.Metadata)
	if !relogin.Disabled {
		t.Fatal("a re-login dropped the administrator's explicit disable")
	}

	patched := &coreauth.Auth{Provider: "meta", Disabled: true, Metadata: map[string]any{
		"disabled": false, "disabled_by": "cliproxyapi", "disabled_reason": "no_dca_token",
	}}
	syncAuthFileDisabledState(patched)
	if _, ok := patched.Metadata["disabled_by"]; ok || patched.Disabled {
		t.Fatalf("field patch enabling the credential kept the marker: %#v", patched.Metadata)
	}
}
