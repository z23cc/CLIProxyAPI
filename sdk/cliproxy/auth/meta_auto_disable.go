package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
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
//   - pending: a rejection was observed; the credential is blocked and a confirmation
//     runs once NextRefreshAfter is due.
//   - retry: the confirmation hit a transient failure (network error, 5xx, a failed
//     save of the minted key); it is tried again on a backoff and never leads to a
//     disable by itself.
//
// A confirmation that is rejected again marks the credential "confirmed". It stays
// blocked and parked until the step that persists the disable takes over.
//
// Every mutation of the state runs under the per-auth mutation gate (metaADMutate, or
// MarkResult and updateInternalLocked, which hold it), so a concurrent credential save
// can never overwrite a transition.
const (
	metaADStatePending = "pending"
	metaADStateRetry   = "retry"

	// Reasons are part of the management API contract.
	metaADReasonMintRejected   = "mint_rejected"
	metaADReasonNewKeyRejected = "new_key_rejected"
	metaADReasonNoDCAToken     = "no_dca_token"

	// metaADConfirmDelay is how long a rejection waits before it is confirmed.
	metaADConfirmDelay = 2 * time.Minute
	// metaADReplacedKeyWindow is how long a key minted to replace a rejected key is
	// considered "fresh": a second rejection inside the window skips the extra mint.
	metaADReplacedKeyWindow = 24 * time.Hour
	// metaADConfirmedHold parks a confirmed credential's NextRefreshAfter far enough
	// out to stay non-zero, which keeps it from reading as a terminal unauthorized failure.
	metaADConfirmedHold = 24 * time.Hour
)

// metaADRetryBackoff is the retry schedule after a transient confirmation failure.
// Attempts beyond the table repeat the last entry (hourly).
var metaADRetryBackoff = [...]time.Duration{5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour}

var (
	errMetaAutoDisableConfirmed = errors.New("meta auto-disable: credential confirmed unusable")
	errMetaAutoDisableAwaiting  = errors.New("meta auto-disable: credential awaiting confirmation")
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
// state is "pending" or "retry"; ok is false when the credential is not being tracked.
func (a *Auth) MetaAutoDisableStatus() (state, reason string, since time.Time, ok bool) {
	if a == nil || !a.metaAD.tracked(a) {
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
	message := fmt.Sprintf("meta auto-disable pending (%s)", reason)
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

// metaADMarkConfirmed records that the confirmation failed: the credential is dead.
// It stays blocked and parked; persisting the disable is a separate step.
func metaADMarkConfirmed(auth *Auth, now time.Time) {
	auth.metaAD.confirmed = true
	metaADApplyBlocked(auth, now.Add(metaADConfirmedHold), auth.metaAD.reason)
	log.WithFields(log.Fields{"auth_id": auth.ID, "provider": "meta", "reason": auth.metaAD.reason}).
		Warnf("meta auto-disable: %s confirmed unusable (%s)", metaADDisplayName(auth), auth.metaAD.reason)
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
// NextRefreshAfter has already passed when it is consulted. A confirmed credential
// is never refreshed again.
func metaAutoDisableRefreshDue(auth *Auth) (due, tracked bool) {
	if auth == nil || auth.metaAD.state == "" || !metaADEligible(auth) || !auth.metaAD.tracked(auth) {
		return false, false
	}
	return !auth.metaAD.confirmed, true
}

// metaAutoDisableScheduleAt is the nextRefreshCheckAt hook for a tracked credential
// whose NextRefreshAfter has passed. Meta has no refresh lead, so without it a due
// credential would be dropped from the refresh loop.
func metaAutoDisableScheduleAt(now time.Time, auth *Auth) (next time.Time, schedule, tracked bool) {
	due, tracked := metaAutoDisableRefreshDue(auth)
	if !tracked {
		return time.Time{}, false, false
	}
	if !due {
		return time.Time{}, false, true
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
//   - Reasons that never re-mint (no_dca_token, new_key_rejected) settle their
//     confirmation here, and the Meta executor is not called: with no dca_token its
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
	if auth.metaAD.confirmed {
		return true, errMetaAutoDisableConfirmed
	}
	now := time.Now()
	switch {
	case auth.metaAD.reason != metaADReasonMintRejected:
		m.metaADMutate(auth.ID, func(live *Auth) bool {
			if !live.metaAD.tracked(live) || live.metaAD.confirmed {
				return false
			}
			metaADMarkConfirmed(live, now)
			return true
		})
		return true, errMetaAutoDisableConfirmed
	case metaADDCAToken(auth) == "":
		m.metaADMutate(auth.ID, func(live *Auth) bool {
			if !live.metaAD.tracked(live) {
				return false
			}
			live.metaAD.clearPending()
			metaADClearRejectionLeftovers(live, now)
			return true
		})
		return true, errMetaAutoDisableAwaiting
	default:
		return false, nil
	}
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
	handled := false
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
		switch {
		case tracked && live.metaAD.confirmed:
			handled = true
			return false
		case tracked && rejected:
			handled = true
			metaADMarkConfirmed(live, now)
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
	return handled
}

// metaAutoDisableOnRefreshSaveError runs when a successful mint could not be saved.
// The credential keeps its old key, so a tracked one must not be left with the
// refresh job's pending marker cleared to zero (which would read as a terminal
// unauthorized failure): it goes back to retry with a real confirmation time.
func (m *Manager) metaAutoDisableOnRefreshSaveError(id string, before *Auth) {
	if !metaADEligible(before) || !before.metaAD.tracked(before) {
		return
	}
	now := time.Now()
	m.metaADMutate(id, func(live *Auth) bool {
		if !live.metaAD.tracked(live) || live.metaAD.confirmed || !live.metaAD.since.Equal(before.metaAD.since) {
			return false
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
	if auth == nil || existing == nil ||
		auth.Disabled || auth.Status == StatusDisabled || existing.Disabled || existing.Status == StatusDisabled {
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
