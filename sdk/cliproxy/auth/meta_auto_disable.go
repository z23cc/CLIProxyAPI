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
//   - retry: the confirmation hit a transient failure (network error, 5xx); it is tried
//     again on a backoff and never leads to a disable by itself.
//
// A confirmation that is rejected again marks the credential "confirmed". It stays
// blocked and parked until the step that persists the disable takes over.
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

var errMetaAutoDisableConfirmed = errors.New("meta auto-disable: credential confirmed unusable")

// metaAutoDisableState is the per-credential in-memory auto-disable state.
// It is a value type so Auth.Clone copies it.
type metaAutoDisableState struct {
	state     string
	reason    string
	since     time.Time
	attempts  int
	confirmed bool
	// cred fingerprints the credential values when the state was entered. A mismatch
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

func (s metaAutoDisableState) replacedWithin(token string, now time.Time) bool {
	if s.replacedKey == "" || strings.TrimSpace(token) == "" {
		return false
	}
	return s.replacedKey == metaADTokenFingerprint(token) && now.Sub(s.replacedAt) < metaADReplacedKeyWindow
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

// metaADFingerprint identifies a Meta credential by its outer access token (the key)
// and its dca_token only. The Meta executor rewrites several other slots (Attributes
// api_key/access_token/base_url, Metadata last_refresh) on every successful mint, so
// hashing them would change the fingerprint on a mint that left the credential as it was.
func metaADFingerprint(auth *Auth) string {
	if auth == nil {
		return ""
	}
	h := sha256.New()
	_, _ = h.Write([]byte(authOuterAccessToken(auth)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(metaADDCAToken(auth)))
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// metaADDCAToken mirrors how the Meta executor finds the device token.
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

// metaADBlocks reports whether selection must skip the credential. It is checked
// by isAuthBlockedForModel so the block holds for every model, whatever per-model
// cooldowns exist or have expired.
func metaADBlocks(auth *Auth) bool {
	return auth != nil && auth.metaAD.state != "" && metaADEligible(auth) && auth.metaAD.tracked(auth)
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
		// A 401 on a key that was already replaced says nothing about the live key.
		if failedToken != "" && !authMatchesTokenPartition(live, failedToken) {
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
		case live.metaAD.replacedWithin(failedToken, now):
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

// metaAutoDisableOnPrepareError runs when the first mint of a credential that only
// has a dca_token failed in PrepareRequestAuth.
func (m *Manager) metaAutoDisableOnPrepareError(auth *Auth, err error) {
	if auth == nil || !metaADMintRejected(err) || !metaADEligible(auth) || !m.metaAutoDisableEnabled() {
		return
	}
	now := time.Now()
	m.metaADMutate(auth.ID, func(live *Auth) bool {
		if !metaADEligible(live) || live.metaAD.tracked(live) {
			return false
		}
		metaADEnterPending(live, metaADReasonMintRejected, now)
		return true
	})
}

// metaAutoDisablePreRefresh runs before a refresh mints a key. Reasons that never
// re-mint (no_dca_token, new_key_rejected) settle their confirmation here, and the
// Meta executor is not called: with no dca_token its Refresh is a successful no-op
// that would otherwise read as a recovery. It reports true when the refresh must stop.
func (m *Manager) metaAutoDisablePreRefresh(auth *Auth, force bool) bool {
	if force || !metaADEligible(auth) || !auth.metaAD.tracked(auth) || !m.metaAutoDisableEnabled() {
		return false
	}
	if !auth.metaAD.confirmed && auth.metaAD.reason == metaADReasonMintRejected {
		return false
	}
	now := time.Now()
	m.metaADMutate(auth.ID, func(live *Auth) bool {
		if !live.metaAD.tracked(live) || live.metaAD.confirmed {
			return false
		}
		metaADMarkConfirmed(live, now)
		return true
	})
	return true
}

// metaAutoDisableOnRefreshError classifies a failed refresh of a Meta credential on
// the live auth. The caller holds m.mu. handled means the generic failure handling must
// not run; changed means the live auth was mutated.
func (m *Manager) metaAutoDisableOnRefreshError(live *Auth, err error, force bool, now time.Time) (handled, changed bool) {
	if !metaADEligible(live) {
		return false, false
	}
	if !m.metaAutoDisableEnabled() {
		// The switch was turned off: drop the tracking and let the generic handling run.
		if live.metaAD.state != "" {
			live.metaAD.clearPending()
			return false, true
		}
		return false, false
	}
	rejected := metaADMintRejected(err)
	switch {
	case live.metaAD.tracked(live) && live.metaAD.confirmed:
		return true, false
	case live.metaAD.tracked(live) && rejected:
		metaADMarkConfirmed(live, now)
		return true, true
	case live.metaAD.tracked(live):
		metaADEnterRetry(live, now)
		return true, true
	case rejected && !force:
		// An operator-forced refresh is not evidence that the key is dead.
		metaADEnterPending(live, metaADReasonMintRejected, now)
		return true, true
	default:
		return false, false
	}
}

// metaAutoDisableAfterRefresh runs after a successful refresh was committed. It ends
// the tracking of a credential that was awaiting confirmation (or sends it back to
// retry when the mint left the credentials unchanged, so it cannot be restored) and stamps the replaced-key window when the mint followed a rejected key.
// before is the credential as it was handed to the refresh. It returns a fresh
// snapshot when the live auth changed.
func (m *Manager) metaAutoDisableAfterRefresh(saved, before *Auth, failedToken string) *Auth {
	if saved == nil || !metaADEligible(saved) {
		return saved
	}
	wasTracked := before.metaAD.tracked(before)
	enabled := m.metaAutoDisableEnabled()
	stamp := enabled && failedToken != "" && !wasTracked
	if !wasTracked && !stamp {
		return saved
	}
	now := time.Now()
	changed := m.metaADMutate(saved.ID, func(live *Auth) bool {
		if !metaADEligible(live) {
			return false
		}
		if wasTracked && live.metaAD.state != "" && live.metaAD.since.Equal(before.metaAD.since) {
			if enabled && live.metaAD.tracked(live) {
				// The credential fingerprint is unchanged, so the mint handed back the key
				// upstream already rejected: that is not a recovery.
				metaADEnterRetry(live, now)
			} else {
				// Recovery of the blocked shape (Unavailable, cooldown, 401 model states) is
				// done by the generic refresh commit; only the in-memory tracking is cleared here.
				live.metaAD.clearPending()
			}
			return true
		}
		if stamp {
			live.metaAD.replacedKey = metaADTokenFingerprint(authOuterAccessToken(live))
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
