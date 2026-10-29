package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"golang.org/x/net/context"
)

const museAccountUnavailableCode = "muse_account_unavailable"

// museAccountIndexPattern matches the shape of an auth index. Only values of this shape are echoed
// back in the 409 message, so client-controlled text can never reach the downstream gateway's
// error keyword matching.
var museAccountIndexPattern = regexp.MustCompile(`^[0-9a-f]{1,64}$`)

// museAccountPin records that this request was locked to one auth by the X-Muse-Account request header.
// A nil pin means the request is not locked, and every method then behaves like the unpinned path.
type museAccountPin struct {
	index   string
	authID  string
	manager *coreauth.Manager
}

// applyMuseAccountPin resolves the X-Muse-Account request header into a pinned auth.
// The header is ignored for internal executions, for requests that already carry an explicit pin,
// for websocket upgrades and in Home mode. An unknown index fails before the auth manager is called.
func (h *BaseAPIHandler) applyMuseAccountPin(ctx context.Context, meta map[string]any, execOptions modelExecutionOptions) (*museAccountPin, *interfaces.ErrorMessage) {
	if execOptions.InternalSource || h.AuthManager == nil || h.AuthManager.HomeEnabled() || pinnedAuthIDFromContext(ctx) != "" {
		return nil, nil
	}
	index := museAccountHeaderFromContext(ctx)
	if index == "" {
		return nil, nil
	}
	pin := &museAccountPin{index: index, manager: h.AuthManager}
	for _, auth := range h.AuthManager.List() {
		if strings.EqualFold(strings.TrimSpace(auth.EnsureIndex()), index) {
			pin.authID = auth.ID
			break
		}
	}
	if pin.authID == "" {
		return nil, pin.unavailableMessage("not_found", 0, 0)
	}
	meta[coreexecutor.PinnedAuthMetadataKey] = pin.authID
	return pin, nil
}

func museAccountHeaderFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	ginCtx, ok := ctx.Value("gin").(*gin.Context)
	if !ok || ginCtx == nil || ginCtx.Request == nil || websocket.IsWebSocketUpgrade(ginCtx.Request) {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(ginCtx.GetHeader(logging.MuseAccountHeader)))
}

// errorMessage converts an auth manager error into an HTTP error message. For a pinned request, failures
// that make the locked account unusable become 409 muse_account_unavailable so the client drops the
// pin; everything else (plain rate limits, 5xx, network errors) is passed through unchanged.
func (p *museAccountPin) errorMessage(err error, model string) *interfaces.ErrorMessage {
	msg := executionErrorMessage(err)
	if p == nil || err == nil || msg.DirectResponse {
		return msg
	}
	// Auth selection failures and model cooldown come first: the cooldown error reports status 429
	// although no upstream call was made.
	if cooldown := isModelCooldownError(err); cooldown || isAuthSelectionUnavailable(err) {
		reason, retryAfter := p.stateReason(model)
		// The cooldown error is proof the locked account is cooling down even when its model state
		// is keyed by an alias or upstream model name that the request model does not match.
		if cooldown && reason == "model_unsupported" {
			reason = "cooling_down"
		}
		if cooldown && reason == "cooling_down" && retryAfter <= 0 {
			retryAfter = retryAfterFromHeaders(err)
		}
		return p.unavailableMessage(reason, 0, retryAfter)
	}
	upstreamStatus := statusFromError(err)
	switch upstreamStatus {
	case http.StatusUnauthorized:
		return p.unavailableMessage("unauthorized", upstreamStatus, 0)
	case http.StatusPaymentRequired:
		return p.unavailableMessage("payment_required", upstreamStatus, 0)
	case http.StatusForbidden:
		return p.unavailableMessage("forbidden", upstreamStatus, 0)
	case http.StatusNotFound:
		return p.unavailableMessage("model_unavailable", upstreamStatus, 0)
	case http.StatusTooManyRequests:
		var scoped interface{ IsCredentialScoped() bool }
		if errors.As(err, &scoped) && scoped != nil && scoped.IsCredentialScoped() {
			var retry interface{ RetryAfter() *time.Duration }
			var retryAfter time.Duration
			if errors.As(err, &retry) && retry != nil {
				if d := retry.RetryAfter(); d != nil {
					retryAfter = *d
				}
			}
			return p.unavailableMessage("quota_exhausted", upstreamStatus, retryAfter)
		}
	}
	return msg
}

// retryAfterFromHeaders reads the Retry-After seconds a cooldown error exposes.
func retryAfterFromHeaders(err error) time.Duration {
	var withHeaders interface{ Headers() http.Header }
	if !errors.As(err, &withHeaders) || withHeaders == nil {
		return 0
	}
	seconds, errParse := strconv.Atoi(strings.TrimSpace(withHeaders.Headers().Get("Retry-After")))
	if errParse != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func isModelCooldownError(err error) bool {
	var marker interface{ IsModelCooldown() bool }
	return errors.As(err, &marker) && marker != nil && marker.IsModelCooldown()
}

// stateReason explains a selection failure from the locked account's current state.
func (p *museAccountPin) stateReason(model string) (string, time.Duration) {
	auth, ok := p.manager.GetByID(p.authID)
	if !ok {
		return "not_found", 0
	}
	if auth.Disabled || auth.Status == coreauth.StatusDisabled || coreauth.HasUnauthorizedAuthFailure(auth) {
		return "disabled", 0
	}
	if _, _, _, tracked := auth.MetaAutoDisableStatus(); tracked {
		return "disabled", 0
	}
	if remaining := cooldownRemaining(auth, model, time.Now()); remaining > 0 {
		return "cooling_down", remaining
	}
	return "model_unsupported", 0
}

// cooldownRemaining returns how long the auth stays blocked for the model by cooldown or quota.
func cooldownRemaining(auth *coreauth.Auth, model string, now time.Time) time.Duration {
	var until time.Time
	consider := func(unavailable, exceeded bool, nextRetry, nextRecover time.Time) {
		if unavailable && nextRetry.After(until) {
			until = nextRetry
		}
		if exceeded && nextRecover.After(until) {
			until = nextRecover
		}
	}
	if len(auth.ModelStates) == 0 {
		consider(auth.Unavailable, auth.Quota.Exceeded, auth.NextRetryAfter, auth.Quota.NextRecoverAt)
	} else {
		consider(false, auth.Quota.Exceeded && auth.Quota.Reason == "credential_quota", time.Time{}, auth.Quota.NextRecoverAt)
		key := thinking.ParseSuffix(strings.TrimSpace(model)).ModelName
		for name, state := range auth.ModelStates {
			if state != nil && thinking.ParseSuffix(strings.TrimSpace(name)).ModelName == key {
				consider(state.Unavailable, state.Quota.Exceeded, state.NextRetryAfter, state.Quota.NextRecoverAt)
			}
		}
	}
	if !until.After(now) {
		return 0
	}
	return until.Sub(now)
}

// museAccountUnavailableError renders the fixed 409 body. Its text is valid JSON, which the error
// response writer returns as the response body unchanged.
type museAccountUnavailableError struct {
	body string
}

func (e *museAccountUnavailableError) Error() string { return e.body }

func (e *museAccountUnavailableError) StatusCode() int { return http.StatusConflict }

// unavailableMessage builds the 409 response. The message uses a fixed template and never includes
// upstream error text; upstream details are limited to numeric fields under error.metadata.
func (p *museAccountPin) unavailableMessage(reason string, upstreamStatus int, retryAfter time.Duration) *interfaces.ErrorMessage {
	index := p.index
	if !museAccountIndexPattern.MatchString(index) {
		index = "invalid"
	}
	type metadata struct {
		Reason            string `json:"reason"`
		UpstreamStatus    int    `json:"upstream_status"`
		RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
	}
	type detail struct {
		Type     string   `json:"type"`
		Code     string   `json:"code"`
		Message  string   `json:"message"`
		Metadata metadata `json:"metadata"`
	}
	body := struct {
		Error detail `json:"error"`
	}{detail{
		Type:    "invalid_request_error",
		Code:    museAccountUnavailableCode,
		Message: fmt.Sprintf("muse account %s is unavailable (%s)", index, reason),
		Metadata: metadata{
			Reason:            reason,
			UpstreamStatus:    upstreamStatus,
			RetryAfterSeconds: int(math.Ceil(retryAfter.Seconds())),
		},
	}}
	data, errMarshal := json.Marshal(body)
	if errMarshal != nil {
		data = []byte(fmt.Sprintf(`{"error":{"type":"invalid_request_error","code":%q,"message":"muse account is unavailable"}}`, museAccountUnavailableCode))
	}
	return &interfaces.ErrorMessage{StatusCode: http.StatusConflict, Error: &museAccountUnavailableError{body: string(data)}}
}
