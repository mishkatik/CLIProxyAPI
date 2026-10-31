package auth

import (
	"context"
	"strconv"
	"strings"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const (
	codexDefaultPrimaryWindowMinutes   = 300
	codexDefaultSecondaryWindowMinutes = 10080
	maxQuotaResetAfter                 = 366 * 24 * time.Hour
)

// SoonestResetSelector prefers the credential whose quota window resets soonest.
//
// Capacity left in a subscription window is lost when the window resets, so burning the
// credential closest to its reset first keeps the quota of the other credentials for later.
// Credentials are ranked by the reset of their long (weekly) window and then by the reset of
// their short (5h) window, read from the passive quota snapshot in Auth.Quota.Signals.
// Claude and Codex credentials report these watermarks. When no candidate carries a future
// reset time, for example other providers or credentials not used since startup, the
// selector falls back to round-robin.
type SoonestResetSelector struct {
	fallback RoundRobinSelector
}

// quotaResetKey holds the next reset of a credential's long and short quota windows.
// A zero time means the reset is unknown or already passed.
type quotaResetKey struct {
	long  time.Time
	short time.Time
}

func (k quotaResetKey) known() bool {
	return !k.long.IsZero() || !k.short.IsZero()
}

func (k quotaResetKey) before(other quotaResetKey) bool {
	if !k.long.Equal(other.long) {
		return resetBefore(k.long, other.long)
	}
	return resetBefore(k.short, other.short)
}

// resetBefore orders reset times ascending and places unknown (zero) times last.
func resetBefore(a, b time.Time) bool {
	if a.IsZero() {
		return false
	}
	if b.IsZero() {
		return true
	}
	return a.Before(b)
}

// Pick selects the available auth whose quota window resets soonest. Ties keep the
// ID-sorted candidate order, so the choice is deterministic.
func (s *SoonestResetSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	now := time.Now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)

	var best *Auth
	var bestKey quotaResetKey
	for _, auth := range available {
		key := quotaResetKeyForAuth(auth, now)
		if !key.known() {
			continue
		}
		if best == nil || key.before(bestKey) {
			best = auth
			bestKey = key
		}
	}
	if best != nil {
		return best, nil
	}
	return s.fallback.Pick(ctx, provider, model, opts, available)
}

func quotaResetKeyForAuth(auth *Auth, now time.Time) quotaResetKey {
	if auth == nil || len(auth.Quota.Signals) == 0 {
		return quotaResetKey{}
	}
	signals := auth.Quota.Signals
	switch strings.ToLower(strings.TrimSpace(auth.Provider)) {
	case "claude":
		return quotaResetKey{
			long:  futureQuotaSignalTime(signals["Anthropic-Ratelimit-Unified-7d-Reset"], now),
			short: futureQuotaSignalTime(signals["Anthropic-Ratelimit-Unified-5h-Reset"], now),
		}
	case "codex":
		// Codex does not pin the weekly limit to a fixed window name (a Pro plan may report
		// it as the primary window), so the longer window is chosen by its reported length.
		primary := codexQuotaWindowFromSignals(signals, "Primary", codexDefaultPrimaryWindowMinutes, auth.Quota.ObservedAt, now)
		secondary := codexQuotaWindowFromSignals(signals, "Secondary", codexDefaultSecondaryWindowMinutes, auth.Quota.ObservedAt, now)
		if primary.minutes > secondary.minutes {
			return quotaResetKey{long: primary.reset, short: secondary.reset}
		}
		return quotaResetKey{long: secondary.reset, short: primary.reset}
	default:
		return quotaResetKey{}
	}
}

// codexQuotaWindow describes one Codex rate-limit window from the passive quota snapshot.
// A window absent from the snapshot has zero minutes so it never outranks a reported one.
type codexQuotaWindow struct {
	minutes int64
	reset   time.Time
}

func codexQuotaWindowFromSignals(signals map[string]string, name string, defaultMinutes int64, observedAt, now time.Time) codexQuotaWindow {
	prefix := "X-Codex-" + name + "-"
	resetAt, hasResetAt := signals[prefix+"Reset-At"]
	resetAfter, hasResetAfter := signals[prefix+"Reset-After-Seconds"]
	rawMinutes, hasMinutes := signals[prefix+"Window-Minutes"]
	if !hasResetAt && !hasResetAfter && !hasMinutes {
		return codexQuotaWindow{}
	}

	window := codexQuotaWindow{minutes: defaultMinutes}
	if minutes, errParse := strconv.ParseInt(strings.TrimSpace(rawMinutes), 10, 64); errParse == nil && minutes > 0 {
		window.minutes = minutes
	}
	window.reset = futureQuotaSignalTime(resetAt, now)
	if window.reset.IsZero() && !observedAt.IsZero() {
		seconds, errParse := strconv.ParseInt(strings.TrimSpace(resetAfter), 10, 64)
		if errParse == nil && seconds > 0 && seconds <= int64(maxQuotaResetAfter/time.Second) {
			if reset := observedAt.Add(time.Duration(seconds) * time.Second); reset.After(now) {
				window.reset = reset
			}
		}
	}
	return window
}

// futureQuotaSignalTime parses a reset watermark carried as unix seconds or RFC3339 and
// returns it only when it is still in the future.
func futureQuotaSignalTime(raw string, now time.Time) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	var reset time.Time
	if seconds, errParse := strconv.ParseInt(raw, 10, 64); errParse == nil {
		if seconds <= 0 {
			return time.Time{}
		}
		reset = time.Unix(seconds, 0)
	} else if parsed, errParseTime := time.Parse(time.RFC3339, raw); errParseTime == nil {
		reset = parsed
	} else {
		return time.Time{}
	}
	if !reset.After(now) {
		return time.Time{}
	}
	return reset
}
