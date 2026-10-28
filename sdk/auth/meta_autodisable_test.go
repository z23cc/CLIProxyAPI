package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	metaauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/meta"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// These tests drive the Meta auto-disable feature through exported APIs only, with the
// real FileTokenStore: the disable must reach the credential file and survive a reload.

const (
	metaADTestPrimaryFile = "aa-primary.json"
	metaADTestBackupFile  = "bb-backup.json"
	metaADTestModel       = "meta-autodisable-model"
	metaADTestDeadKey     = "dead-key-0"
)

// metaADTestExecutor answers 401 for the dead key and mints nothing: every Refresh is a
// rejected mint (HTTP 401), unless refresh is overridden.
type metaADTestExecutor struct {
	mu      sync.Mutex
	calls   map[string]int
	refresh func(*coreauth.Auth) (*coreauth.Auth, error)
}

func newMetaADTestExecutor() *metaADTestExecutor {
	return &metaADTestExecutor{calls: make(map[string]int)}
}

func (e *metaADTestExecutor) Identifier() string { return "meta" }

func metaADTestKey(a *coreauth.Auth) string {
	if a.Attributes != nil {
		if k := strings.TrimSpace(a.Attributes["api_key"]); k != "" {
			return k
		}
	}
	if k, _ := a.Metadata["api_key"].(string); strings.TrimSpace(k) != "" {
		return strings.TrimSpace(k)
	}
	if k, _ := a.Metadata["access_token"].(string); strings.TrimSpace(k) != "" {
		return strings.TrimSpace(k)
	}
	return ""
}

func (e *metaADTestExecutor) Execute(_ context.Context, a *coreauth.Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.mu.Lock()
	e.calls[a.ID]++
	e.mu.Unlock()
	if metaADTestKey(a) == metaADTestDeadKey {
		return cliproxyexecutor.Response{}, &coreauth.Error{HTTPStatus: http.StatusUnauthorized, Message: "key rejected"}
	}
	return cliproxyexecutor.Response{Payload: []byte(a.ID)}, nil
}

func (e *metaADTestExecutor) ExecuteStream(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, &coreauth.Error{HTTPStatus: http.StatusNotImplemented, Message: "not implemented"}
}

func (e *metaADTestExecutor) Refresh(_ context.Context, a *coreauth.Auth) (*coreauth.Auth, error) {
	e.mu.Lock()
	fn := e.refresh
	e.mu.Unlock()
	if fn != nil {
		return fn(a)
	}
	return nil, fmt.Errorf("meta executor: mint API key failed: %w", &metaauth.MintError{Status: http.StatusUnauthorized, Body: "x"})
}

func (e *metaADTestExecutor) CountTokens(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, &coreauth.Error{HTTPStatus: http.StatusNotImplemented, Message: "not implemented"}
}

func (e *metaADTestExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func (e *metaADTestExecutor) callsFor(id string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls[id]
}

func metaADTestPrimaryMetadata() map[string]any {
	return map[string]any{
		"type":         "meta",
		"api_key":      metaADTestDeadKey,
		"access_token": metaADTestDeadKey,
		"dca_token":    "dca:primary",
		"base_url":     "https://meta.example.invalid",
		"email":        "primary@example.invalid",
		"priority":     5,
		"proxy_url":    "http://127.0.0.1:9",
	}
}

func metaADTestBackupMetadata() map[string]any {
	return map[string]any{
		"type":         "meta",
		"api_key":      "good-key",
		"access_token": "good-key",
		"dca_token":    "dca:backup",
		"base_url":     "https://meta.example.invalid",
		"email":        "backup@example.invalid",
	}
}

func metaADTestWriteFile(t *testing.T, dir, name string, content map[string]any) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(content, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", name, err)
	}
	if err = os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return raw
}

func metaADTestReadFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return raw
}

func metaADTestReadJSON(t *testing.T, dir, name string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(metaADTestReadFile(t, dir, name), &out); err != nil {
		t.Fatalf("unmarshal %s: %v", name, err)
	}
	return out
}

func metaADTestSwitch() *config.Config {
	return &config.Config{Routing: config.RoutingConfig{MetaAutoDisable: config.MetaAutoDisableConfig{Enabled: true}}}
}

// metaADTestManager builds a manager over store with the loaded auths registered the way
// the watcher does (the file is the source of truth, so nothing is written back).
func metaADTestManager(t *testing.T, store *FileTokenStore, exec *metaADTestExecutor, auths []*coreauth.Auth) *coreauth.Manager {
	t.Helper()
	m := coreauth.NewManager(store, nil, nil)
	m.RegisterExecutor(exec)
	m.SetConfig(metaADTestSwitch())
	reg := registry.GetGlobalRegistry()
	for _, a := range auths {
		id := a.ID
		reg.RegisterClient(id, "meta", []*registry.ModelInfo{{ID: metaADTestModel}})
		t.Cleanup(func() { reg.UnregisterClient(id) })
		if _, err := m.Register(coreauth.WithSkipPersist(context.Background()), a); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}
	return m
}

func metaADTestListed(t *testing.T, store *FileTokenStore) []*coreauth.Auth {
	t.Helper()
	auths, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return auths
}

func metaADTestFind(t *testing.T, auths []*coreauth.Auth, id string) *coreauth.Auth {
	t.Helper()
	for _, a := range auths {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("auth %s not listed", id)
	return nil
}

func metaADTestExecute(m *coreauth.Manager) (string, error) {
	resp, err := m.Execute(context.Background(), []string{"meta"}, cliproxyexecutor.Request{Model: metaADTestModel}, cliproxyexecutor.Options{})
	return string(resp.Payload), err
}

// metaADTestEnterPending runs the request path: the primary's key is rejected, its mint is
// rejected too, the backup serves the request and the primary is pending.
func metaADTestEnterPending(t *testing.T, m *coreauth.Manager, exec *metaADTestExecutor, primaryID string) {
	t.Helper()
	payload, err := metaADTestExecute(m)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if payload != metaADTestBackupFile {
		t.Fatalf("payload = %q, want the backup", payload)
	}
	if exec.callsFor(primaryID) != 1 {
		t.Fatalf("primary calls = %d, want 1", exec.callsFor(primaryID))
	}
	primary, ok := m.GetByID(primaryID)
	if !ok {
		t.Fatalf("primary missing")
	}
	if state, reason, _, tracked := primary.MetaAutoDisableStatus(); !tracked || state != "pending" || reason != "mint_rejected" {
		t.Fatalf("MetaAutoDisableStatus = (%q, %q, %v), want pending mint_rejected", state, reason, tracked)
	}
}

func metaADTestRequireDisabledInMemory(t *testing.T, m *coreauth.Manager, id string) {
	t.Helper()
	got, ok := m.GetByID(id)
	if !ok {
		t.Fatalf("auth %s missing", id)
	}
	if !got.Disabled || got.Status != coreauth.StatusDisabled || got.StatusMessage != "disabled (meta mint_rejected)" {
		t.Fatalf("in memory: Disabled=%v Status=%v StatusMessage=%q", got.Disabled, got.Status, got.StatusMessage)
	}
	if _, _, _, tracked := got.MetaAutoDisableStatus(); tracked {
		t.Fatalf("a disabled credential must not report an auto-disable state")
	}
}

func metaADTestRequireMarkers(t *testing.T, file map[string]any, before, after time.Time) {
	t.Helper()
	if file["disabled"] != true || file["disabled_by"] != "cliproxyapi" || file["disabled_reason"] != "mint_rejected" {
		t.Fatalf("file markers = disabled:%v disabled_by:%v disabled_reason:%v", file["disabled"], file["disabled_by"], file["disabled_reason"])
	}
	raw, _ := file["disabled_at"].(string)
	at, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("disabled_at = %q: %v", raw, err)
	}
	if at.Location() != time.UTC {
		t.Fatalf("disabled_at = %q, want UTC", raw)
	}
	if at.Before(before.Add(-time.Second)) || at.After(after.Add(time.Second)) {
		t.Fatalf("disabled_at = %v, want within [%v, %v]", at, before, after)
	}
}

func metaADTestRequireFieldsKept(t *testing.T, file, original map[string]any) {
	t.Helper()
	for key, want := range original {
		got, ok := file[key]
		if !ok {
			t.Fatalf("field %q was dropped from the file", key)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("field %q = %v, want %v", key, got, want)
		}
	}
}

// metaADTestReloadedNeverSelected registers the reloaded auths in a new manager and checks
// that the disabled primary is never selected.
func metaADTestReloadedNeverSelected(t *testing.T, store *FileTokenStore, primaryID string) {
	t.Helper()
	reloaded := metaADTestListed(t, store)
	primary := metaADTestFind(t, reloaded, primaryID)
	if !primary.Disabled || primary.Status != coreauth.StatusDisabled {
		t.Fatalf("reloaded: Disabled=%v Status=%v, want disabled", primary.Disabled, primary.Status)
	}
	exec := newMetaADTestExecutor()
	m := metaADTestManager(t, store, exec, reloaded)
	for i := 0; i < 3; i++ {
		payload, err := metaADTestExecute(m)
		if err != nil || payload != metaADTestBackupFile {
			t.Fatalf("Execute #%d = (%q, %v), want the backup", i, payload, err)
		}
	}
	if exec.callsFor(primaryID) != 0 {
		t.Fatalf("the disabled primary was selected %d times", exec.callsFor(primaryID))
	}
}

func TestMetaAutoDisable_FileLoadedCredentialDisabledOnDiskAndReloaded(t *testing.T) {
	dir := t.TempDir()
	original := metaADTestPrimaryMetadata()
	metaADTestWriteFile(t, dir, metaADTestPrimaryFile, original)
	metaADTestWriteFile(t, dir, metaADTestBackupFile, metaADTestBackupMetadata())
	store := NewFileTokenStore()
	store.SetBaseDir(dir)

	exec := newMetaADTestExecutor()
	loaded := metaADTestListed(t, store)
	if p := metaADTestFind(t, loaded, metaADTestPrimaryFile); p.Storage != nil {
		t.Fatalf("a file-loaded credential must have no Storage")
	}
	m := metaADTestManager(t, store, exec, loaded)
	metaADTestEnterPending(t, m, exec, metaADTestPrimaryFile)

	before := time.Now()
	if _, err := m.ForceRefreshAuth(context.Background(), metaADTestPrimaryFile); err == nil {
		t.Fatalf("ForceRefreshAuth error = nil, want the rejected mint")
	}
	after := time.Now()

	metaADTestRequireDisabledInMemory(t, m, metaADTestPrimaryFile)
	file := metaADTestReadJSON(t, dir, metaADTestPrimaryFile)
	metaADTestRequireMarkers(t, file, before, after)
	metaADTestRequireFieldsKept(t, file, original)
	metaADTestReloadedNeverSelected(t, store, metaADTestPrimaryFile)
}

func TestMetaAutoDisable_MetaTokenStorageCredentialDisabledOnDiskAndReloaded(t *testing.T) {
	dir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	metaADTestWriteFile(t, dir, metaADTestBackupFile, metaADTestBackupMetadata())

	// The shape sdk/auth/meta.go Login builds.
	tokenStorage := &metaauth.MetaTokenStorage{
		Type:        "meta",
		AuthKind:    "oauth",
		AccessToken: "dca:primary",
		DCAToken:    "dca:primary",
		APIKey:      metaADTestDeadKey,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		LastRefresh: "2026-01-01T00:00:00Z",
		BaseURL:     "https://meta.example.invalid",
		Email:       "primary@example.invalid",
		Name:        "Primary",
	}
	record := &coreauth.Auth{
		ID:       metaADTestPrimaryFile,
		Provider: "meta",
		FileName: metaADTestPrimaryFile,
		Label:    "primary@example.invalid",
		Storage:  tokenStorage,
		Metadata: map[string]any{
			"type":         "meta",
			"access_token": tokenStorage.AccessToken,
			"token_type":   tokenStorage.TokenType,
			"expires_in":   tokenStorage.ExpiresIn,
			"last_refresh": tokenStorage.LastRefresh,
			"base_url":     tokenStorage.BaseURL,
			"auth_kind":    "oauth",
			"api_key":      tokenStorage.APIKey,
			"dca_token":    tokenStorage.DCAToken,
			"email":        tokenStorage.Email,
			"name":         tokenStorage.Name,
			"priority":     5,
		},
		Attributes: map[string]string{
			"auth_kind": "oauth",
			"base_url":  tokenStorage.BaseURL,
			"api_key":   tokenStorage.APIKey,
			"dca_token": tokenStorage.DCAToken,
			"email":     tokenStorage.Email,
		},
	}
	if _, err := store.Save(coreauth.WithAuthCreationIntent(context.Background()), record); err != nil {
		t.Fatalf("Save: %v", err)
	}
	original := metaADTestReadJSON(t, dir, metaADTestPrimaryFile)

	exec := newMetaADTestExecutor()
	auths := []*coreauth.Auth{record, metaADTestFind(t, metaADTestListed(t, store), metaADTestBackupFile)}
	m := metaADTestManager(t, store, exec, auths)
	metaADTestEnterPending(t, m, exec, metaADTestPrimaryFile)

	before := time.Now()
	if _, err := m.ForceRefreshAuth(context.Background(), metaADTestPrimaryFile); err == nil {
		t.Fatalf("ForceRefreshAuth error = nil, want the rejected mint")
	}
	after := time.Now()

	metaADTestRequireDisabledInMemory(t, m, metaADTestPrimaryFile)
	file := metaADTestReadJSON(t, dir, metaADTestPrimaryFile)
	metaADTestRequireMarkers(t, file, before, after)
	for key, want := range original {
		if key == "disabled" {
			continue
		}
		if got, ok := file[key]; !ok || fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("field %q = %v (present %v), want %v", key, got, ok, want)
		}
	}
	metaADTestReloadedNeverSelected(t, store, metaADTestPrimaryFile)
}

func TestMetaAutoDisable_UsageStatisticsMarkerIsNeverOverwritten(t *testing.T) {
	marker := func(content map[string]any) map[string]any {
		content["disabled"] = true
		content["disabled_by"] = "usage-statistics"
		content["disabled_reason"] = "quota"
		content["disabled_at"] = "2026-01-01T00:00:00Z"
		return content
	}

	t.Run("disabled_before_load", func(t *testing.T) {
		dir := t.TempDir()
		raw := metaADTestWriteFile(t, dir, metaADTestPrimaryFile, marker(metaADTestPrimaryMetadata()))
		metaADTestWriteFile(t, dir, metaADTestBackupFile, metaADTestBackupMetadata())
		store := NewFileTokenStore()
		store.SetBaseDir(dir)
		exec := newMetaADTestExecutor()
		m := metaADTestManager(t, store, exec, metaADTestListed(t, store))

		for i := 0; i < 2; i++ {
			if payload, err := metaADTestExecute(m); err != nil || payload != metaADTestBackupFile {
				t.Fatalf("Execute = (%q, %v), want the backup", payload, err)
			}
		}
		_, _ = m.ForceRefreshAuth(context.Background(), metaADTestPrimaryFile)
		if got := metaADTestReadFile(t, dir, metaADTestPrimaryFile); !bytes.Equal(got, raw) {
			t.Fatalf("the usage-statistics file was rewritten:\n%s", got)
		}
	})

	t.Run("marker_lands_after_pending", func(t *testing.T) {
		dir := t.TempDir()
		metaADTestWriteFile(t, dir, metaADTestPrimaryFile, metaADTestPrimaryMetadata())
		metaADTestWriteFile(t, dir, metaADTestBackupFile, metaADTestBackupMetadata())
		store := NewFileTokenStore()
		store.SetBaseDir(dir)
		exec := newMetaADTestExecutor()
		m := metaADTestManager(t, store, exec, metaADTestListed(t, store))
		metaADTestEnterPending(t, m, exec, metaADTestPrimaryFile)

		// The plugin disables the file; the watcher reloads it into the manager.
		raw := metaADTestWriteFile(t, dir, metaADTestPrimaryFile, marker(metaADTestPrimaryMetadata()))
		reloaded := metaADTestFind(t, metaADTestListed(t, store), metaADTestPrimaryFile)
		if _, err := m.Update(coreauth.WithSkipPersist(context.Background()), reloaded); err != nil {
			t.Fatalf("Update: %v", err)
		}

		_, _ = m.ForceRefreshAuth(context.Background(), metaADTestPrimaryFile)

		if got := metaADTestReadFile(t, dir, metaADTestPrimaryFile); !bytes.Equal(got, raw) {
			t.Fatalf("the usage-statistics file was rewritten:\n%s", got)
		}
		if bytes.Contains(metaADTestReadFile(t, dir, metaADTestPrimaryFile), []byte("cliproxyapi")) {
			t.Fatalf("a cliproxyapi marker appeared in the file")
		}
		got, _ := m.GetByID(metaADTestPrimaryFile)
		if !got.Disabled || got.Status != coreauth.StatusDisabled {
			t.Fatalf("in memory: Disabled=%v Status=%v, want disabled by the plugin", got.Disabled, got.Status)
		}
		if _, _, _, tracked := got.MetaAutoDisableStatus(); tracked {
			t.Fatalf("a credential disabled by the plugin must not stay tracked")
		}
	})
}

func TestMetaAutoDisable_DisableWriteSkippedWhenCredentialReplaced(t *testing.T) {
	dir := t.TempDir()
	metaADTestWriteFile(t, dir, metaADTestPrimaryFile, metaADTestPrimaryMetadata())
	metaADTestWriteFile(t, dir, metaADTestBackupFile, metaADTestBackupMetadata())
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	exec := newMetaADTestExecutor()
	m := metaADTestManager(t, store, exec, metaADTestListed(t, store))
	metaADTestEnterPending(t, m, exec, metaADTestPrimaryFile)

	// A re-login replaces the file; the watcher reloads it into the manager.
	relogin := metaADTestPrimaryMetadata()
	relogin["api_key"] = "relogin-key"
	relogin["access_token"] = "relogin-key"
	relogin["dca_token"] = "dca:relogin"
	raw := metaADTestWriteFile(t, dir, metaADTestPrimaryFile, relogin)
	reloaded := metaADTestFind(t, metaADTestListed(t, store), metaADTestPrimaryFile)
	if _, err := m.Update(coreauth.WithSkipPersist(context.Background()), reloaded); err != nil {
		t.Fatalf("Update: %v", err)
	}

	_, _ = m.ForceRefreshAuth(context.Background(), metaADTestPrimaryFile)

	if got := metaADTestReadFile(t, dir, metaADTestPrimaryFile); !bytes.Equal(got, raw) {
		t.Fatalf("the re-login file was rewritten:\n%s", got)
	}
	got, _ := m.GetByID(metaADTestPrimaryFile)
	if got.Disabled || got.Status == coreauth.StatusDisabled {
		t.Fatalf("the re-logged-in credential was disabled")
	}
}

func TestMetaAutoDisable_FailedSaveIsNotPublished(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("cannot make the credential file unwritable on this platform or user")
	}
	dir := t.TempDir()
	metaADTestWriteFile(t, dir, metaADTestPrimaryFile, metaADTestPrimaryMetadata())
	metaADTestWriteFile(t, dir, metaADTestBackupFile, metaADTestBackupMetadata())
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	exec := newMetaADTestExecutor()
	m := metaADTestManager(t, store, exec, metaADTestListed(t, store))
	metaADTestEnterPending(t, m, exec, metaADTestPrimaryFile)

	path := filepath.Join(dir, metaADTestPrimaryFile)
	original := metaADTestReadFile(t, dir, metaADTestPrimaryFile)
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	_, _ = m.ForceRefreshAuth(context.Background(), metaADTestPrimaryFile)

	got, _ := m.GetByID(metaADTestPrimaryFile)
	if got.Disabled || got.Status == coreauth.StatusDisabled {
		t.Fatalf("a disable that could not be saved was published in memory")
	}
	if !got.Unavailable || got.NextRefreshAfter.IsZero() {
		t.Fatalf("Unavailable=%v NextRefreshAfter=%v, want blocked with a retry time", got.Unavailable, got.NextRefreshAfter)
	}
	if now := time.Now(); !got.NextRefreshAfter.After(now) {
		t.Fatalf("NextRefreshAfter = %v is not in the future", got.NextRefreshAfter)
	}
	if payload, err := metaADTestExecute(m); err != nil || payload != metaADTestBackupFile {
		t.Fatalf("Execute = (%q, %v), want the backup (the primary stays blocked)", payload, err)
	}
	if !bytes.Equal(metaADTestReadFile(t, dir, metaADTestPrimaryFile), original) {
		t.Fatalf("the file changed although the save failed")
	}

	// Once the file is writable again, a forced refresh whose mint is rejected again
	// completes the pending disable write.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	before := time.Now()
	if _, err := m.ForceRefreshAuth(context.Background(), metaADTestPrimaryFile); err == nil {
		t.Fatalf("ForceRefreshAuth error = nil, want the rejected mint")
	}
	after := time.Now()
	metaADTestRequireDisabledInMemory(t, m, metaADTestPrimaryFile)
	metaADTestRequireMarkers(t, metaADTestReadJSON(t, dir, metaADTestPrimaryFile), before, after)
	metaADTestReloadedNeverSelected(t, store, metaADTestPrimaryFile)
}
