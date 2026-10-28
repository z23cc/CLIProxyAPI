package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	metaauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/meta"
	log "github.com/sirupsen/logrus"
)

// Meta auto-disable detects Meta credentials whose API key can no longer be minted
// and keeps them out of rotation while the verdict is confirmed. The state lives only
// in memory, on the Auth itself (Auth.metaAD). The hooks in the generic refresh,
// selection and lifecycle code are thin calls into this file.
//
// States:
//
//   - pending: a rejection was observed; the credential is blocked and a confirmation
//     runs once NextRefreshAfter is due.
//
//   - retry: the confirmation hit a transient failure (network error, 5xx, a failed
//     save of the minted key); it is tried again on a backoff and never leads to a
//     disable by itself.
//
//   - capped: the verdict is dead, but the per-hour disable cap is used up; the credential
//     stays blocked and is confirmed again (a mint first, when the reason is
//     mint_rejected) after metaADCapRetryDelay.
//
// A confirmation that is rejected again marks the credential "confirmed" (the verdict is
// dead) and the disable is written at once through Manager.Modify. The flag stays set,
// with a non-zero retry time, only while that write cannot be completed (a failed save);
// the write is then retried and the credential is never minted for again.
//
// Every mutation of the state runs under the per-auth mutation gate (metaADMutate, or
// MarkResult and updateInternalLocked, which hold it), so a concurrent credential save
// can never overwrite a transition.
const (
	metaADStatePending = "pending"
	metaADStateRetry   = "retry"
	metaADStateCapped  = "capped"

	// Reasons are part of the management API contract.
	metaADReasonMintRejected   = "mint_rejected"
	metaADReasonNewKeyRejected = "new_key_rejected"
	metaADReasonNoDCAToken     = "no_dca_token"

	// metaADConfirmDelay is how long a rejection waits before it is confirmed.
	metaADConfirmDelay = 2 * time.Minute
	// metaADReplacedKeyWindow is how long a key minted to replace a rejected key is
	// considered "fresh": a second rejection inside the window skips the extra mint.
	metaADReplacedKeyWindow = 24 * time.Hour
	// metaADWriteRetryDelay is when a confirmed credential's disable is written again after
	// a failed save. It also keeps NextRefreshAfter non-zero, so the credential never
	// reads as a terminal unauthorized failure.
	metaADWriteRetryDelay = 10 * time.Minute
	// metaADCapRetryDelay is how long a credential held back by the hourly cap waits
	// before it is confirmed again.
	metaADCapRetryDelay = 10 * time.Minute
	// metaADCapWindow is the sliding window of the disable cap.
	metaADCapWindow = time.Hour

	// metaADDisabledBy and the metadata keys below are written into the credential file when
	// the disable is persisted. Their names are consumed by the management API and supernewapi.
	metaADDisabledBy    = "cliproxyapi"
	metaADKeyDisabledBy = "disabled_by"
	metaADKeyReason     = "disabled_reason"
	metaADKeyDisabledAt = "disabled_at"
)

// metaADRetryBackoff is the retry schedule after a transient confirmation failure.
// Attempts beyond the table repeat the last entry (hourly).
var metaADRetryBackoff = [...]time.Duration{5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour}

var (
	errMetaAutoDisableConfirmed = errors.New("meta auto-disable: credential confirmed unusable")
	errMetaAutoDisableAwaiting  = errors.New("meta auto-disable: credential awaiting confirmation")
	// errMetaADWriteSkipped means a guard found the disable no longer applicable; nothing was changed.
	errMetaADWriteSkipped = errors.New("meta auto-disable: disable not written")
)

// metaAutoDisableState is the per-credential in-memory auto-disable state.
// It is a value type so Auth.Clone copies it.
type metaAutoDisableState struct {
	state     string
	reason    string
	since     time.Time
	attempts  int
	confirmed bool
	// cred fingerprints the key and dca_token when the state was entered. A mismatch
	// means the credential was replaced (for example a re-login) and the state is void.
	cred  string
	epoch uint64

	// replacedKey fingerprints the key minted because the previous key was rejected,
	// and replacedAt records when. It outlives the pending state.
	replacedKey string
	replacedAt  time.Time
}

// metaADEpisode identifies one pending/confirmed episode of one credential. Evidence and
// writes carry the episode their caller saw, and only act when the live episode is the
// same one: after a re-login a fresh episode must not inherit an older episode's verdict.
type metaADEpisode struct {
	cred   string
	epoch  uint64
	since  time.Time
	reason string
}

func (s metaAutoDisableState) episode() metaADEpisode {
	return metaADEpisode{cred: s.cred, epoch: s.epoch, since: s.since, reason: s.reason}
}

// is reports whether s is the episode e (and a tracked one).
func (s metaAutoDisableState) is(e metaADEpisode) bool {
	return s.state != "" && s.cred == e.cred && s.epoch == e.epoch && s.since.Equal(e.since) && s.reason == e.reason
}

func (s metaAutoDisableState) tracked(auth *Auth) bool {
	return s.state != "" && s.cred == metaADFingerprint(auth)
}

// replacedWithin reports whether key is the key that was minted to replace a rejected
// key, and that mint is still inside the window.
func (s metaAutoDisableState) replacedWithin(key string, now time.Time) bool {
	if s.replacedKey == "" || strings.TrimSpace(key) == "" {
		return false
	}
	return s.replacedKey == metaADTokenFingerprint(key) && now.Sub(s.replacedAt) < metaADReplacedKeyWindow
}

// clearPending drops the pending/retry bookkeeping and keeps the replaced-key window.
func (s *metaAutoDisableState) clearPending() {
	*s = metaAutoDisableState{replacedKey: s.replacedKey, replacedAt: s.replacedAt}
}

// MetaAutoDisableStatus reports the in-memory auto-disable state of a Meta credential.
// state is "pending", "retry" or "capped"; ok is false when the credential is not being
// tracked (including once its disable has been written).
func (a *Auth) MetaAutoDisableStatus() (state, reason string, since time.Time, ok bool) {
	if a == nil || a.Disabled || a.Status == StatusDisabled || !a.metaAD.tracked(a) {
		return "", "", time.Time{}, false
	}
	return a.metaAD.state, a.metaAD.reason, a.metaAD.since, true
}

func (m *Manager) metaAutoDisableEnabled() bool {
	cfg := m.runtimeConfigSnapshot()
	return cfg != nil && cfg.Routing.MetaAutoDisable.Enabled
}

// metaADEligible limits the feature to Meta credentials loaded from auth files.
// Keys from the meta-api-key config entries are never touched.
func metaADEligible(auth *Auth) bool {
	return auth != nil && strings.EqualFold(strings.TrimSpace(auth.Provider), "meta") &&
		!IsConfigAPIKeyAuth(auth) && !auth.Disabled && auth.Status != StatusDisabled
}

// metaADMintRejected reports whether err is a Meta mint rejection (HTTP 401 or 403).
// It does not rely on isUnauthorizedError, which ignores 403.
func metaADMintRejected(err error) bool {
	var mintErr *metaauth.MintError
	if !errors.As(err, &mintErr) || mintErr == nil {
		return false
	}
	switch mintErr.StatusCode() {
	case http.StatusUnauthorized, http.StatusForbidden:
		return true
	default:
		return false
	}
}

func metaADRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > len(metaADRetryBackoff) {
		attempt = len(metaADRetryBackoff)
	}
	return metaADRetryBackoff[attempt-1]
}

func metaADTokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:8])
}

// metaADKey mirrors MetaExecutor's metaCreds token lookup: the API key that is sent
// upstream. Keys that look like device tokens ("dca:" prefix) are skipped.
func metaADKey(auth *Auth) string {
	if auth == nil {
		return ""
	}
	usable := func(value string) string {
		value = strings.TrimSpace(value)
		if value == "" || strings.HasPrefix(value, "dca:") {
			return ""
		}
		return value
	}
	if auth.Attributes != nil {
		if k := usable(auth.Attributes["api_key"]); k != "" {
			return k
		}
		if t := usable(auth.Attributes["access_token"]); t != "" {
			return t
		}
	}
	if k := usable(authMetadataString(auth, "api_key")); k != "" {
		return k
	}
	if t := usable(authMetadataString(auth, "access_token")); t != "" {
		return t
	}
	if ms, ok := auth.Storage.(*metaauth.MetaTokenStorage); ok && ms != nil {
		if ms.APIKey != "" {
			return ms.APIKey
		}
		return usable(ms.AccessToken)
	}
	return ""
}

// metaADDCAToken mirrors MetaExecutor's extractDCAToken lookup.
func metaADDCAToken(auth *Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Attributes != nil {
		if d := strings.TrimSpace(auth.Attributes["dca_token"]); d != "" {
			return d
		}
		if t := strings.TrimSpace(auth.Attributes["access_token"]); strings.HasPrefix(t, "dca:") {
			return t
		}
	}
	if d := authMetadataString(auth, "dca_token"); d != "" {
		return d
	}
	if t := authMetadataString(auth, "access_token"); strings.HasPrefix(t, "dca:") {
		return t
	}
	if ms, ok := auth.Storage.(*metaauth.MetaTokenStorage); ok && ms != nil {
		if ms.DCAToken != "" {
			return ms.DCAToken
		}
		if strings.HasPrefix(ms.AccessToken, "dca:") {
			return ms.AccessToken
		}
	}
	return ""
}

// metaADFingerprint identifies a Meta credential by the key and the dca_token the
// executor would use, and nothing else. The executor rewrites other slots (Attributes
// base_url, Metadata last_refresh, ...) on every successful mint, so hashing them
// would change the fingerprint on a mint that left the credential as it was.
// CredentialsChanged does not compare dca_token, so it cannot stand in for this.
func metaADFingerprint(auth *Auth) string {
	if auth == nil {
		return ""
	}
	h := sha256.New()
	_, _ = h.Write([]byte(metaADKey(auth)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(metaADDCAToken(auth)))
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// metaADSameCredential reports whether a and b carry the same key and dca_token.
func metaADSameCredential(a, b *Auth) bool {
	return metaADFingerprint(a) == metaADFingerprint(b)
}

func metaADDisplayName(auth *Auth) string {
	if name := strings.TrimSpace(auth.FileName); name != "" {
		return filepath.Base(name)
	}
	return auth.ID
}

// metaADApplyBlocked puts the live auth into the blocked shape shared by every
// tracked state. NextRefreshAfter stays non-zero so the credential never reads as a
// terminal unauthorized failure (see hasUnauthorizedAuthFailure).
func metaADApplyBlocked(auth *Auth, due time.Time, reason string) {
	label := "pending"
	if auth.metaAD.state == metaADStateCapped {
		label = "capped"
	}
	message := fmt.Sprintf("meta auto-disable %s (%s)", label, reason)
	auth.Unavailable = true
	auth.Status = StatusError
	auth.NextRefreshAfter = due
	auth.NextRetryAfter = time.Time{}
	auth.RefreshFailures = 0
	auth.StatusMessage = message
	auth.LastError = &Error{Code: reason, Message: message, HTTPStatus: http.StatusUnauthorized}
}

func metaADEnterPending(auth *Auth, reason string, now time.Time) {
	auth.metaAD = metaAutoDisableState{
		state:       metaADStatePending,
		reason:      reason,
		since:       now,
		cred:        metaADFingerprint(auth),
		epoch:       auth.RegistrationEpoch,
		replacedKey: auth.metaAD.replacedKey,
		replacedAt:  auth.metaAD.replacedAt,
	}
	metaADApplyBlocked(auth, now.Add(metaADConfirmDelay), reason)
	log.WithFields(log.Fields{"auth_id": auth.ID, "provider": "meta", "reason": reason}).
		Warnf("meta auto-disable: %s awaiting confirmation (%s)", metaADDisplayName(auth), reason)
}

func metaADEnterRetry(auth *Auth, now time.Time) {
	auth.metaAD.state = metaADStateRetry
	auth.metaAD.attempts++
	auth.metaAD.confirmed = false
	metaADApplyBlocked(auth, now.Add(metaADRetryDelay(auth.metaAD.attempts)), auth.metaAD.reason)
	log.WithFields(log.Fields{"auth_id": auth.ID, "provider": "meta", "reason": auth.metaAD.reason, "attempt": auth.metaAD.attempts}).
		Warnf("meta auto-disable: %s confirmation hit a transient failure, retrying", metaADDisplayName(auth))
}

// metaADMarkConfirmed records that the confirmation failed: the credential is dead. It
// stays blocked with a retry time until the disable is written, so a failed write is
// retried later and the credential is never minted for again.
func metaADMarkConfirmed(auth *Auth, now time.Time) {
	auth.metaAD.state = metaADStatePending
	auth.metaAD.confirmed = true
	metaADApplyBlocked(auth, now.Add(metaADWriteRetryDelay), auth.metaAD.reason)
	log.WithFields(log.Fields{"auth_id": auth.ID, "provider": "meta", "reason": auth.metaAD.reason}).
		Warnf("meta auto-disable: %s confirmed unusable (%s)", metaADDisplayName(auth), auth.metaAD.reason)
}

// metaADEnterCapped holds a dead credential back because the hourly disable cap is used
// up. It stays blocked and is confirmed again after metaADCapRetryDelay.
func metaADEnterCapped(auth *Auth, now time.Time) {
	auth.metaAD.state = metaADStateCapped
	auth.metaAD.confirmed = false
	metaADApplyBlocked(auth, now.Add(metaADCapRetryDelay), auth.metaAD.reason)
}

// metaADCancelTracking ends the tracking and lifts the block that the feature itself put on
// the credential (the synthetic 401, Unavailable, StatusError), so it falls back to the normal
// handling. Model states and cooldowns of other causes are left alone. It is used when the
// switch was turned off while a write was pending.
func metaADCancelTracking(auth *Auth, now time.Time) {
	auth.metaAD.clearPending()
	if metaADRejectionError(auth.LastError) {
		if !(auth.Quota.Exceeded && auth.Quota.NextRecoverAt.After(now)) {
			auth.Unavailable = false
		}
		if auth.Status == StatusError {
			auth.Status = StatusActive
		}
		auth.NextRetryAfter = time.Time{}
		auth.StatusMessage = ""
		auth.LastError = nil
	}
	auth.NextRefreshAfter = time.Time{}
	auth.RefreshFailures = 0
}

// metaADRejectionError reports whether err is the 401/403 a rejected mint or key leaves behind.
func metaADRejectionError(err *Error) bool {
	if err == nil {
		return false
	}
	code := err.StatusCode()
	return code == http.StatusUnauthorized || code == http.StatusForbidden
}

// metaADClearRejectionLeftovers clears the unavailability that a rejection (a mint or
// key refused with 401/403) left on the auth and on its model states, and reports
// whether it changed anything the cooldown store tracks. The generic recovery only
// recognises 401 and invalid_grant, so a 403 would otherwise keep the credential
// cooling for 30 minutes after a confirmed mint. Cooldowns that come from other
// causes (quota, transient errors, at auth level or on a model) are left alone: the
// auth-level state is only touched when its LastError is the 401/403, and the
// aggregate availability is only recomputed when a model state was actually reset
// (from the remaining model states, exactly as a model-scoped result does).
func metaADClearRejectionLeftovers(auth *Auth, now time.Time) bool {
	changed := false
	authLevel := metaADRejectionError(auth.LastError)
	if authLevel {
		if !(auth.Quota.Exceeded && auth.Quota.NextRecoverAt.After(now)) {
			auth.Unavailable = false
		}
		if auth.Status == StatusError {
			auth.Status = StatusActive
		}
		auth.NextRetryAfter = time.Time{}
		auth.StatusMessage = ""
		auth.LastError = nil
		changed = true
	}
	auth.NextRefreshAfter = time.Time{}
	auth.RefreshFailures = 0

	modelReset := false
	for _, state := range auth.ModelStates {
		if state == nil || !metaADRejectionError(state.LastError) {
			continue
		}
		if state.Quota.Exceeded && (state.Quota.NextRecoverAt.IsZero() || state.Quota.NextRecoverAt.After(now)) {
			continue
		}
		resetModelState(state, now)
		modelReset = true
	}
	if modelReset {
		// With model states present the aggregate follows them, as after any model-scoped result.
		updateAggregatedAvailability(auth, now)
		changed = true
	}
	return changed
}

// metaADBlocks reports whether selection must skip the credential. It is checked
// by isAuthBlockedForModel so the block holds for every model, whatever per-model
// cooldowns exist or have expired.
func metaADBlocks(auth *Auth) bool {
	return auth != nil && auth.metaAD.state != "" && metaADEligible(auth) && auth.metaAD.tracked(auth)
}

// metaAutoDisableCanMint reports whether the manager may re-mint a Meta credential on
// a 401 although authHasRefreshCredential does not see a dca_token: the executor also
// accepts a "dca:" access token and a MetaTokenStorage. It only widens the set when
// the feature is on, so behaviour with the switch off is unchanged.
func (m *Manager) metaAutoDisableCanMint(auth *Auth) bool {
	return metaADEligible(auth) && metaADDCAToken(auth) != "" && m.metaAutoDisableEnabled()
}

// metaAutoDisableRefreshDue is the shouldRefresh hook for a tracked credential.
// NextRefreshAfter has already passed when it is consulted, so every tracked state is
// due: a confirmation, or the retry of a disable write that could not be saved.
func metaAutoDisableRefreshDue(auth *Auth) (due, tracked bool) {
	if auth == nil || auth.metaAD.state == "" || !metaADEligible(auth) || !auth.metaAD.tracked(auth) {
		return false, false
	}
	return true, true
}

// metaAutoDisableScheduleAt is the nextRefreshCheckAt hook for a tracked credential
// whose NextRefreshAfter has passed. Meta has no refresh lead, so without it a due
// credential would be dropped from the refresh loop.
func metaAutoDisableScheduleAt(now time.Time, auth *Auth) (next time.Time, schedule, tracked bool) {
	if _, tracked := metaAutoDisableRefreshDue(auth); !tracked {
		return time.Time{}, false, false
	}
	return now, true, true
}

// metaADMutate applies fn to the live auth under the per-auth mutation gate and
// m.mu, then republishes it. It returns a snapshot of the changed auth, or nil
// when fn changed nothing. Callers must not hold m.mu or the mutation gate.
func (m *Manager) metaADMutate(id string, fn func(live *Auth) bool) *Auth {
	if m == nil || id == "" {
		return nil
	}
	release := m.lockAuthMutation(id)
	defer release()
	m.mu.Lock()
	live := m.auths[id]
	if live == nil || !fn(live) {
		m.mu.Unlock()
		return nil
	}
	live.Generation++
	live.UpdatedAt = time.Now()
	snapshot := live.Clone()
	if m.scheduler != nil {
		m.scheduler.upsertAuth(snapshot.Clone())
	}
	m.mu.Unlock()
	m.queueRefreshReschedule(id)
	return snapshot
}

// metaAutoDisableOnUnauthorized runs when a request hit a 401 on a Meta credential,
// before the in-request re-mint. It reports true when the request must not mint again:
// the credential is already tracked, has no dca_token to mint with, or its key was
// itself minted to replace a rejected key inside the window. The request still fails
// over to the next credential.
func (m *Manager) metaAutoDisableOnUnauthorized(auth *Auth, failedToken string) bool {
	if !metaADEligible(auth) || !m.metaAutoDisableEnabled() {
		return false
	}
	now := time.Now()
	handled := false
	m.metaADMutate(auth.ID, func(live *Auth) bool {
		if !metaADEligible(live) {
			return false
		}
		key := metaADKey(live)
		// A 401 on a key that was already replaced says nothing about the live key.
		if failedToken != "" && failedToken != key && !authMatchesTokenPartition(live, failedToken) {
			return false
		}
		if live.metaAD.tracked(live) {
			handled = true
			return false
		}
		reason := ""
		switch {
		case metaADDCAToken(live) == "":
			reason = metaADReasonNoDCAToken
		case live.metaAD.replacedWithin(key, now):
			reason = metaADReasonNewKeyRejected
		}
		if reason == "" {
			return false
		}
		handled = true
		metaADEnterPending(live, reason, now)
		return true
	})
	return handled
}

// metaAutoDisableOnRejectedKey runs from MarkResult, which holds the per-auth mutation
// gate and m.mu, for every recorded failure that rejected rejectedToken with a 401. This
// is where the failure of an in-request retry is recorded for all execution paths
// (Execute, streaming, bootstrap, ...): if the rejected key is the one just minted to
// replace a rejected key, the new key is dead too, and the credential enters pending
// without another mint. It reports whether the credential entered pending, so the caller
// can queue the confirmation in the refresh loop.
func (m *Manager) metaAutoDisableOnRejectedKey(live *Auth, rejectedToken string, now time.Time) bool {
	if !metaADEligible(live) || live.metaAD.tracked(live) || !m.metaAutoDisableEnabled() {
		return false
	}
	key := metaADKey(live)
	if key == "" || (rejectedToken != "" && rejectedToken != key && !authMatchesTokenPartition(live, rejectedToken)) {
		return false
	}
	if !live.metaAD.replacedWithin(key, now) {
		return false
	}
	metaADEnterPending(live, metaADReasonNewKeyRejected, now)
	return true
}

// metaAutoDisableOnPrepareError runs when the first mint of a credential that only
// has a dca_token failed in PrepareRequestAuth. target is the credential as it was
// when the mint started; a failure that outlived a credential replacement is ignored.
func (m *Manager) metaAutoDisableOnPrepareError(target *Auth, err error) {
	if target == nil || !metaADMintRejected(err) || !metaADEligible(target) || !m.metaAutoDisableEnabled() {
		return
	}
	now := time.Now()
	m.metaADMutate(target.ID, func(live *Auth) bool {
		if !metaADEligible(live) || live.metaAD.tracked(live) ||
			live.RegistrationEpoch != target.RegistrationEpoch || !metaADSameCredential(target, live) {
			return false
		}
		metaADEnterPending(live, metaADReasonMintRejected, now)
		return true
	})
}

// metaAutoDisablePreRefresh runs before a refresh mints a key and reports whether the
// refresh must stop (with the error to return).
//   - A request-path refresh (failedToken set) never mints while the credential is
//     tracked: a concurrent request that queued behind the refresh lock must not
//     bypass the confirmation delay.
//   - A credential whose verdict is already dead (a disable write is being retried), or
//     whose reason never re-mints (no_dca_token, new_key_rejected), settles here by
//     writing the disable, and the Meta executor is not called: with no dca_token its
//     Refresh is a successful no-op that would otherwise read as a recovery.
//   - A tracked credential that cannot be minted for (no dca_token) is released
//     instead of retrying forever.
//
// An operator-forced refresh always goes through.
func (m *Manager) metaAutoDisablePreRefresh(auth *Auth, force bool, failedToken string) (bool, error) {
	if force || !metaADEligible(auth) || !auth.metaAD.tracked(auth) || !m.metaAutoDisableEnabled() {
		return false, nil
	}
	if failedToken != "" {
		return true, errMetaAutoDisableAwaiting
	}
	if auth.metaAD.confirmed || auth.metaAD.reason != metaADReasonMintRejected {
		m.metaAutoDisableSettle(auth.ID, auth.metaAD.episode())
		return true, errMetaAutoDisableConfirmed
	}
	if metaADDCAToken(auth) == "" {
		now := time.Now()
		m.metaADMutate(auth.ID, func(live *Auth) bool {
			if !live.metaAD.tracked(live) {
				return false
			}
			live.metaAD.clearPending()
			metaADClearRejectionLeftovers(live, now)
			return true
		})
		return true, errMetaAutoDisableAwaiting
	}
	return false, nil
}

// metaAutoDisableOnRefreshError classifies a failed refresh of a Meta credential,
// before the generic failure branches. It reports whether the generic handling must
// be skipped. base is the credential as it was handed to the refresh. The whole
// transition runs under the per-auth mutation gate.
func (m *Manager) metaAutoDisableOnRefreshError(id string, base *Auth, err error, force bool, now time.Time) bool {
	// With the switch off and nothing tracked, stay out of the way entirely: no gate.
	if !metaADEligible(base) || (base.metaAD.state == "" && !m.metaAutoDisableEnabled()) {
		return false
	}
	handled, needWrite := false, false
	var episode metaADEpisode
	m.metaADMutate(id, func(live *Auth) bool {
		// Cases the generic code already resolves on its own.
		if !metaADEligible(live) || base.RegistrationEpoch != live.RegistrationEpoch || (hasUnauthorizedAuthFailure(live) && !force) {
			return false
		}
		if !m.metaAutoDisableEnabled() {
			// The switch was turned off: drop the tracking and let the generic handling run.
			if live.metaAD.state != "" {
				live.metaAD.clearPending()
				return true
			}
			return false
		}
		// The credential was replaced while the mint was in flight: the failure belongs to the old one.
		if !metaADSameCredential(base, live) {
			handled = true
			return false
		}
		rejected := metaADMintRejected(err)
		tracked := live.metaAD.tracked(live)
		// The failure is evidence for the episode the refresh started with. An episode that
		// began while the mint was in flight (or a different one) is not confirmed by it.
		if tracked && !(base.metaAD.state != "" && base.metaAD.is(live.metaAD.episode())) {
			handled = true
			return false
		}
		switch {
		case tracked && live.metaAD.confirmed:
			// Only an operator-forced refresh gets here (the loop writes without a mint). A
			// rejected mint completes the disable write that could not be saved; a transient
			// failure proves nothing, so the credential keeps its verdict and its retry time.
			handled = true
			if rejected {
				needWrite = true
				episode = live.metaAD.episode()
			}
			return false
		case tracked && rejected:
			handled = true
			metaADMarkConfirmed(live, now)
			needWrite = true
			episode = live.metaAD.episode()
			return true
		case tracked:
			handled = true
			metaADEnterRetry(live, now)
			return true
		case rejected && !force:
			// An operator-forced refresh is not evidence that the key is dead.
			handled = true
			metaADEnterPending(live, metaADReasonMintRejected, now)
			return true
		default:
			return false
		}
	})
	if needWrite {
		// The gate is released here: Modify takes it itself.
		m.metaAutoDisableWrite(id, episode)
	}
	return handled
}

// metaAutoDisableOnRefreshSaveError runs when a successful mint could not be saved.
// The credential keeps its old key, so a tracked one must not be left with the refresh
// job's pending marker cleared to zero (which would read as a terminal unauthorized
// failure): it goes back to retry with a real confirmation time. A confirmed credential
// (an operator-forced refresh minted for it) loses its dead verdict: the mint just worked,
// so the next confirmation mints again (reason mint_rejected) instead of writing a disable
// for a credential that was rescued.
func (m *Manager) metaAutoDisableOnRefreshSaveError(id string, before *Auth) {
	if !metaADEligible(before) || !before.metaAD.tracked(before) {
		return
	}
	now := time.Now()
	m.metaADMutate(id, func(live *Auth) bool {
		if !live.metaAD.tracked(live) || !live.metaAD.since.Equal(before.metaAD.since) {
			return false
		}
		if live.metaAD.confirmed && metaADDCAToken(live) != "" {
			live.metaAD.reason = metaADReasonMintRejected
		}
		metaADEnterRetry(live, now)
		return true
	})
}

// metaAutoDisableAfterRefresh runs after a successful refresh was committed. mintedKey
// is the key the mint produced. It does nothing unless that key is the one now installed
// (checked under the mutation gate): a refresh that was discarded as stale must not touch
// the credential that replaced it.
// It sends a tracked credential back to retry when the mint left the credentials
// unchanged (so it cannot be restored), and stamps the replaced-key window when the mint
// followed a rejected key and produced a different one. A mint that changed the key was
// already settled inside the commit by metaADFinishUpdate, which ends the tracking and
// clears what the rejection left behind in the same locked step, so no concurrent update
// can slip in between. before is the credential as it was handed to the refresh.
// It returns a fresh snapshot when the live auth changed.
func (m *Manager) metaAutoDisableAfterRefresh(saved, before *Auth, mintedKey, failedToken string) *Auth {
	if saved == nil || !metaADEligible(saved) || mintedKey == "" {
		return saved
	}
	wasTracked := before.metaAD.tracked(before)
	enabled := m.metaAutoDisableEnabled()
	// A mint that hands back the rejected key is no evidence about a replacement key.
	stamp := enabled && failedToken != "" && !wasTracked && mintedKey != metaADKey(before)
	if !wasTracked && !stamp {
		return saved
	}
	now := time.Now()
	changed := m.metaADMutate(saved.ID, func(live *Auth) bool {
		if !metaADEligible(live) || metaADKey(live) != mintedKey {
			return false
		}
		if wasTracked && live.metaAD.state != "" && live.metaAD.since.Equal(before.metaAD.since) {
			if enabled && live.metaAD.tracked(live) {
				// The fingerprint is unchanged, so the mint handed back the key upstream
				// already rejected: that is not a recovery.
				metaADEnterRetry(live, now)
			} else {
				live.metaAD.clearPending()
			}
			return true
		}
		if stamp {
			live.metaAD.replacedKey = metaADTokenFingerprint(mintedKey)
			live.metaAD.replacedAt = now
			return true
		}
		return false
	})
	if changed != nil {
		return changed
	}
	return saved
}

// metaADFinishUpdate runs inside updateInternalLocked, under the mutation gate, after the
// generic merge. It reports whether it changed cooldown state that the cooldown store tracks.
// Replacing updates (a reload, a re-login) build a new object, so the in-memory state is
// carried over from the live auth; refresh and prepare merges start from the live auth and
// already carry it. Then:
//   - same key and dca_token: the state stays, and a replacing update also gets the
//     confirmation time and blocked shape the generic merge does not copy for every update
//     path;
//   - the key or dca_token the state was entered with is gone (the refresh itself minted a
//     new key, a re-login, a reload): the state is voided, and when it came from a rejected
//     mint the 401/403 leftovers of that rejection are cleared in this same step. Doing it
//     here, and not in a separate step after the commit, leaves no window in which another
//     update could void the state first and strand the leftovers.
func metaADFinishUpdate(auth, existing *Auth, mode updateAuthMode, now time.Time) bool {
	if auth == nil || existing == nil {
		return false
	}
	if auth.Disabled || auth.Status == StatusDisabled || existing.Disabled || existing.Status == StatusDisabled {
		// A disabled credential is not being confirmed any more.
		auth.metaAD.clearPending()
		return false
	}
	if mode == updateModeReplace {
		auth.metaAD = existing.metaAD
	}
	if auth.metaAD.state == "" {
		return false
	}
	if auth.metaAD.tracked(auth) {
		if mode != updateModeReplace {
			return false
		}
		due := existing.NextRefreshAfter
		if auth.NextRefreshAfter.After(due) {
			due = auth.NextRefreshAfter
		}
		if due.IsZero() {
			due = now.Add(metaADConfirmDelay)
		}
		metaADApplyBlocked(auth, due, auth.metaAD.reason)
		return false
	}
	rejectedMint := auth.metaAD.reason == metaADReasonMintRejected
	auth.metaAD.clearPending()
	changed := false
	if rejectedMint {
		changed = metaADClearRejectionLeftovers(auth, now)
	}
	// A replacing update inherits the blocked shape from the old object; drop it with the state.
	if mode == updateModeReplace && existing.Unavailable && auth.Unavailable && auth.Status == StatusError {
		auth.Unavailable = false
		auth.Status = StatusActive
		auth.NextRefreshAfter = time.Time{}
		auth.NextRetryAfter = time.Time{}
		auth.StatusMessage = ""
		auth.LastError = nil
		changed = true
	}
	return changed
}

// metaADLimiter is the per-process sliding window behind routing.meta-auto-disable.max-per-hour.
type metaADLimiter struct {
	mu          sync.Mutex
	stamps      []time.Time
	capLoggedAt time.Time
}

// reserve takes a slot for a disable that is about to be written. When the window is full
// it refuses, and reports logCap for the first refusal in each window so the error is
// logged once per window.
func (l *metaADLimiter) reserve(now time.Time, limit int) (ok, logCap bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.stamps[:0]
	for _, stamp := range l.stamps {
		if now.Sub(stamp) < metaADCapWindow {
			kept = append(kept, stamp)
		}
	}
	l.stamps = kept
	if len(l.stamps) >= limit {
		if l.capLoggedAt.IsZero() || now.Sub(l.capLoggedAt) >= metaADCapWindow {
			l.capLoggedAt = now
			return false, true
		}
		return false, false
	}
	l.stamps = append(l.stamps, now)
	return true, false
}

// release gives back a slot taken by reserve when the disable was not written.
func (l *metaADLimiter) release(stamp time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, existing := range l.stamps {
		if existing.Equal(stamp) {
			l.stamps = append(l.stamps[:i], l.stamps[i+1:]...)
			return
		}
	}
}

type metaADPersistRequiredKey struct{}

// metaADPersistContext marks a Manager.Modify whose save must succeed: unlike an ordinary
// update, a disable that cannot be saved must not be published in memory.
func metaADPersistContext() context.Context {
	return context.WithValue(context.Background(), metaADPersistRequiredKey{}, true)
}

// metaADPersistRequired is read by updateInternalLocked to treat a failed save as fatal.
func metaADPersistRequired(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	required, _ := ctx.Value(metaADPersistRequiredKey{}).(bool)
	return required
}

// metaAutoDisableSettle turns a dead verdict into a written disable: it marks the tracked
// credential confirmed (under the mutation gate), then writes. It is used when the verdict
// needs no mint, or is already reached and the write is being retried. episode is the
// episode the caller saw: if the live credential is in another one (it was re-logged-in and
// went pending again meanwhile), nothing happens to it.
func (m *Manager) metaAutoDisableSettle(id string, episode metaADEpisode) {
	live, ok := m.GetByID(id)
	if !ok || !metaADEligible(live) || !live.metaAD.tracked(live) || !live.metaAD.is(episode) {
		return
	}
	if !live.metaAD.confirmed {
		now := time.Now()
		m.metaADMutate(id, func(cur *Auth) bool {
			if !metaADEligible(cur) || !cur.metaAD.tracked(cur) || !cur.metaAD.is(episode) || cur.metaAD.confirmed {
				return false
			}
			metaADMarkConfirmed(cur, now)
			return true
		})
	}
	m.metaAutoDisableWrite(id, episode)
}

// metaAutoDisableWrite persists the disable of a confirmed credential. It must be called
// without the mutation gate or m.mu: Manager.Modify takes the gate itself. The decision was
// made under the gate earlier, so every guard is checked again inside the edit, which runs
// under the gate on the freshest live copy; a credential that was replaced, disabled by
// someone else or re-registered in between is left untouched, and so is a different
// episode than the caller's. The hourly cap is reserved before the write and given back
// when nothing was written.
//
// A failed Store.Save keeps the slot: a store that writes the watched local file first and
// uploads afterwards (object store, Postgres, git) may have landed the disable locally
// already, and refunding would let the local disables exceed the cap. Only a write that
// was skipped, or rejected for a stale registration, gives the slot back. With such a
// store a failed upload leaves the remote copy enabled: the local disable stands until
// the next sync from the remote restores the credential, and a later 401 starts the
// detection again.
func (m *Manager) metaAutoDisableWrite(id string, episode metaADEpisode) {
	live, ok := m.GetByID(id)
	if !ok || !metaADEligible(live) || !live.metaAD.tracked(live) || !live.metaAD.confirmed || !live.metaAD.is(episode) {
		return
	}
	now := time.Now()
	if !m.metaAutoDisableEnabled() {
		// The switch was turned off meanwhile: this credential is not auto-disabled any more.
		m.metaADMutate(id, func(cur *Auth) bool {
			if !cur.metaAD.tracked(cur) || !cur.metaAD.is(episode) {
				return false
			}
			metaADCancelTracking(cur, now)
			return true
		})
		return
	}
	state := live.metaAD
	limit := m.runtimeConfigSnapshot().Routing.MetaAutoDisable.EffectiveMaxPerHour()
	reserved, logCap := m.metaADLimiter.reserve(now, limit)
	if !reserved {
		m.metaADMutate(id, func(cur *Auth) bool {
			if !cur.metaAD.tracked(cur) || !cur.metaAD.confirmed || !cur.metaAD.is(episode) {
				return false
			}
			metaADEnterCapped(cur, now)
			return true
		})
		if logCap {
			log.WithFields(log.Fields{"provider": "meta", "max_per_hour": limit}).
				Errorf("meta auto-disable: hourly disable cap reached; further dead credentials stay blocked and are confirmed again every %s", metaADCapRetryDelay)
		}
		return
	}
	_, committed, err := m.Modify(metaADPersistContext(), id, state.epoch, func(a *Auth) error {
		return m.metaADApplyDisable(a, state, now)
	})
	switch {
	case committed:
		log.WithFields(log.Fields{"auth_id": id, "provider": "meta", "reason": state.reason}).
			Warnf("meta auto-disable: %s disabled (%s)", metaADDisplayName(live), state.reason)
	case err == nil || errors.Is(err, errMetaADWriteSkipped):
		m.metaADLimiter.release(now)
		m.metaADAfterSkippedWrite(id, state, now)
	default:
		// A failed save, or a registration that changed meanwhile (Modify rejected the stale
		// epoch, or the credential is gone): in the latter nothing could have been written.
		if cur, present := m.GetByID(id); !present || cur.RegistrationEpoch != state.epoch {
			m.metaADLimiter.release(now)
		}
		m.metaADRetryWriteLater(id, state, time.Now(), err)
	}
}

// metaADApplyDisable is the edit run by Manager.Modify under the mutation gate. It skips
// (errMetaADWriteSkipped, nothing changed) unless the credential is still the one that was
// confirmed: file-loaded, not disabled by anyone (an administrator or the usage-statistics
// marker), and the same key and dca_token as when it went pending. The registration is
// guarded by Modify itself (expectedEpoch is the epoch recorded at pending entry), and a
// re-registered credential carries no state any more.
func (m *Manager) metaADApplyDisable(a *Auth, state metaAutoDisableState, now time.Time) error {
	if !metaADEligible(a) || !a.metaAD.tracked(a) || !a.metaAD.confirmed ||
		!a.metaAD.since.Equal(state.since) || !m.metaAutoDisableEnabled() {
		return errMetaADWriteSkipped
	}
	reason := a.metaAD.reason
	a.Disabled = true
	a.Status = StatusDisabled
	a.StatusMessage = fmt.Sprintf("disabled (meta %s)", reason)
	a.Unavailable = false
	a.NextRefreshAfter = time.Time{}
	a.NextRetryAfter = time.Time{}
	a.RefreshFailures = 0
	a.LastError = nil
	a.metaAD.clearPending()
	if a.Metadata == nil {
		a.Metadata = make(map[string]any)
	}
	a.Metadata["disabled"] = true
	a.Metadata[metaADKeyDisabledBy] = metaADDisabledBy
	a.Metadata[metaADKeyReason] = reason
	a.Metadata[metaADKeyDisabledAt] = now.UTC().Format(time.RFC3339)
	return nil
}

// metaADAfterSkippedWrite cleans up after a write that a guard skipped. A credential that
// someone else disabled is no longer tracked. If the switch was turned off, the credential
// is released from the feature (tracking and its own block). One that is still tracked gets
// a new retry time of its own: the refresh job that triggered the write holds its
// pendingUntil marker in NextRefreshAfter and zeroes it when it finishes, so that value
// must never be mistaken for a deadline.
func (m *Manager) metaADAfterSkippedWrite(id string, state metaAutoDisableState, now time.Time) {
	episode := state.episode()
	m.metaADMutate(id, func(cur *Auth) bool {
		if cur.Disabled || cur.Status == StatusDisabled {
			if cur.metaAD.state == "" {
				return false
			}
			cur.metaAD.clearPending()
			return true
		}
		if !cur.metaAD.tracked(cur) || !cur.metaAD.is(episode) {
			return false
		}
		if !m.metaAutoDisableEnabled() {
			metaADCancelTracking(cur, now)
			return true
		}
		if !cur.metaAD.confirmed {
			// Another flow moved the credential on (retry, capped) and set its own deadline.
			return false
		}
		due := now.Add(metaADWriteRetryDelay)
		if due.Equal(cur.NextRefreshAfter) {
			due = due.Add(time.Nanosecond)
		}
		metaADApplyBlocked(cur, due, cur.metaAD.reason)
		return true
	})
}

// metaADRetryWriteLater keeps a confirmed credential blocked with a non-zero retry time after
// a failed save, so the write is attempted again and the credential is not minted for.
func (m *Manager) metaADRetryWriteLater(id string, state metaAutoDisableState, now time.Time, cause error) {
	retried := m.metaADMutate(id, func(cur *Auth) bool {
		if !metaADEligible(cur) || !cur.metaAD.tracked(cur) || !cur.metaAD.confirmed ||
			!cur.metaAD.since.Equal(state.since) || cur.RegistrationEpoch != state.epoch {
			return false
		}
		metaADApplyBlocked(cur, now.Add(metaADWriteRetryDelay), cur.metaAD.reason)
		return true
	})
	if retried != nil {
		log.WithFields(log.Fields{"auth_id": id, "provider": "meta", "reason": state.reason}).
			Warnf("meta auto-disable: disabling %s could not be saved, retrying in %s: %v", metaADDisplayName(retried), metaADWriteRetryDelay, cause)
	}
}
