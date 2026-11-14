package auth

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func unixSignal(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}

func claudeResetAuth(id string, weeklyReset, fiveHourReset time.Time) *Auth {
	signals := map[string]string{}
	if !weeklyReset.IsZero() {
		signals["Anthropic-Ratelimit-Unified-7d-Reset"] = unixSignal(weeklyReset)
	}
	if !fiveHourReset.IsZero() {
		signals["Anthropic-Ratelimit-Unified-5h-Reset"] = unixSignal(fiveHourReset)
	}
	return &Auth{ID: id, Provider: "claude", Quota: QuotaState{ObservedAt: time.Now(), Signals: signals}}
}

func withOAuthMetadata(auth *Auth) *Auth {
	auth.Metadata = map[string]any{"email": auth.ID + "@example.com"}
	return auth
}

func TestSoonestResetSelectorPick_PrefersSoonestWeeklyReset(t *testing.T) {
	t.Parallel()

	now := time.Now()
	selector := &SoonestResetSelector{}
	auths := []*Auth{
		claudeResetAuth("a", now.Add(5*24*time.Hour), now.Add(time.Hour)),
		claudeResetAuth("b", now.Add(3*24*time.Hour), now.Add(4*time.Hour)),
		claudeResetAuth("c", now.Add(24*time.Hour), now.Add(4*time.Hour)),
	}

	got, err := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got == nil || got.ID != "c" {
		t.Fatalf("Pick() auth = %v, want c", got)
	}
}

func TestSoonestResetSelectorPick_FiveHourResetBreaksWeeklyTie(t *testing.T) {
	t.Parallel()

	now := time.Now()
	weekly := now.Add(2 * 24 * time.Hour)
	selector := &SoonestResetSelector{}
	auths := []*Auth{
		claudeResetAuth("a", weekly, now.Add(3*time.Hour)),
		claudeResetAuth("b", weekly, now.Add(time.Hour)),
		claudeResetAuth("c", weekly, time.Time{}),
	}

	got, err := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got == nil || got.ID != "b" {
		t.Fatalf("Pick() auth = %v, want b", got)
	}
}

func TestSoonestResetSelectorPick_PassedResetRanksAfterKnownReset(t *testing.T) {
	t.Parallel()

	now := time.Now()
	selector := &SoonestResetSelector{}
	auths := []*Auth{
		claudeResetAuth("a", now.Add(-time.Hour), now.Add(-2*time.Hour)),
		claudeResetAuth("b", now.Add(6*24*time.Hour), time.Time{}),
		{ID: "c", Provider: "claude"},
	}

	got, err := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got == nil || got.ID != "b" {
		t.Fatalf("Pick() auth = %v, want b", got)
	}
}

func TestSoonestResetSelectorPick_FallsBackToRoundRobinWithoutSignals(t *testing.T) {
	t.Parallel()

	selector := &SoonestResetSelector{}
	auths := []*Auth{
		{ID: "a", Provider: "gemini"},
		{ID: "b", Provider: "gemini"},
	}

	for i, want := range []string{"a", "b", "a"} {
		got, err := selector.Pick(context.Background(), "gemini", "", cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatalf("Pick() #%d error = %v", i, err)
		}
		if got == nil || got.ID != want {
			t.Fatalf("Pick() #%d auth = %v, want %s", i, got, want)
		}
	}
}

func TestSoonestResetSelectorPick_HigherPriorityWinsOverSoonerReset(t *testing.T) {
	t.Parallel()

	now := time.Now()
	selector := &SoonestResetSelector{}
	low := claudeResetAuth("a", now.Add(time.Hour), time.Time{})
	low.Attributes = map[string]string{"priority": "0"}
	high := claudeResetAuth("b", now.Add(6*24*time.Hour), time.Time{})
	high.Attributes = map[string]string{"priority": "10"}

	got, err := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, []*Auth{low, high})
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got == nil || got.ID != "b" {
		t.Fatalf("Pick() auth = %v, want b", got)
	}
}

func TestSoonestResetSelectorPick_SkipsCredentialQuotaCooldown(t *testing.T) {
	t.Parallel()

	now := time.Now()
	selector := &SoonestResetSelector{}
	cooling := claudeResetAuth("a", now.Add(time.Hour), time.Time{})
	cooling.Quota.Exceeded = true
	cooling.Quota.Reason = "credential_quota"
	cooling.Quota.NextRecoverAt = now.Add(time.Hour)
	ready := claudeResetAuth("b", now.Add(6*24*time.Hour), time.Time{})

	got, err := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, []*Auth{cooling, ready})
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got == nil || got.ID != "b" {
		t.Fatalf("Pick() auth = %v, want b", got)
	}
}

func TestSoonestResetSelectorPick_ProbesUnobservedOAuthCredential(t *testing.T) {
	t.Parallel()

	now := time.Now()
	selector := &SoonestResetSelector{}
	observed := withOAuthMetadata(claudeResetAuth("a", now.Add(2*24*time.Hour), now.Add(time.Hour)))
	added := withOAuthMetadata(&Auth{ID: "b", Provider: "claude"})

	got, err := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, []*Auth{observed, added})
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got == nil || got.ID != "b" {
		t.Fatalf("Pick() auth = %v, want b", got)
	}
}

func TestSoonestResetSelectorPick_RotatesAmongUnobservedOAuthCredentials(t *testing.T) {
	t.Parallel()

	now := time.Now()
	selector := &SoonestResetSelector{}
	auths := []*Auth{
		withOAuthMetadata(claudeResetAuth("a", now.Add(time.Hour), time.Time{})),
		withOAuthMetadata(&Auth{ID: "b", Provider: "claude"}),
		withOAuthMetadata(claudeResetAuth("c", now.Add(-time.Hour), now.Add(-2*time.Hour))),
	}

	for i, want := range []string{"b", "c", "b"} {
		got, err := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatalf("Pick() #%d error = %v", i, err)
		}
		if got == nil || got.ID != want {
			t.Fatalf("Pick() #%d auth = %v, want %s", i, got, want)
		}
	}
}

func TestSoonestResetSelectorPick_DoesNotProbeAPIKeyCredential(t *testing.T) {
	t.Parallel()

	now := time.Now()
	selector := &SoonestResetSelector{}
	subscription := withOAuthMetadata(claudeResetAuth("a", now.Add(6*24*time.Hour), time.Time{}))
	apiKey := &Auth{ID: "b", Provider: "claude", Attributes: map[string]string{AttributeAPIKey: "sk-test"}}

	got, err := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, []*Auth{subscription, apiKey})
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got == nil || got.ID != "a" {
		t.Fatalf("Pick() auth = %v, want a", got)
	}
}

func TestQuotaResetKeyForAuth_CodexUsesLongerWindow(t *testing.T) {
	t.Parallel()

	now := time.Now()
	weekly := now.Add(4 * 24 * time.Hour).Truncate(time.Second)
	fiveHour := now.Add(2 * time.Hour).Truncate(time.Second)

	primaryWeekly := &Auth{ID: "a", Provider: "codex", Quota: QuotaState{Signals: map[string]string{
		"X-Codex-Primary-Window-Minutes": "10080",
		"X-Codex-Primary-Reset-At":       unixSignal(weekly),
	}}}
	key := quotaResetKeyForAuth(primaryWeekly, now)
	if !key.long.Equal(weekly) || !key.short.IsZero() {
		t.Fatalf("primary weekly key = %+v, want long=%v short=zero", key, weekly)
	}

	defaultWindows := &Auth{ID: "b", Provider: "codex", Quota: QuotaState{Signals: map[string]string{
		"X-Codex-Primary-Reset-At":   unixSignal(fiveHour),
		"X-Codex-Secondary-Reset-At": unixSignal(weekly),
	}}}
	key = quotaResetKeyForAuth(defaultWindows, now)
	if !key.long.Equal(weekly) || !key.short.Equal(fiveHour) {
		t.Fatalf("default windows key = %+v, want long=%v short=%v", key, weekly, fiveHour)
	}
}

func TestQuotaResetKeyForAuth_CodexResetAfterSecondsUsesObservedAt(t *testing.T) {
	t.Parallel()

	now := time.Now()
	observedAt := now.Add(-time.Hour).Truncate(time.Second)
	auth := &Auth{ID: "a", Provider: "codex", Quota: QuotaState{ObservedAt: observedAt, Signals: map[string]string{
		"X-Codex-Secondary-Window-Minutes":      "10080",
		"X-Codex-Secondary-Reset-After-Seconds": "7200",
	}}}

	key := quotaResetKeyForAuth(auth, now)
	if want := observedAt.Add(2 * time.Hour); !key.long.Equal(want) {
		t.Fatalf("long reset = %v, want %v", key.long, want)
	}
}

func TestManagerSoonestResetSelectsObservedSoonestReset(t *testing.T) {
	t.Parallel()

	manager := NewManager(nil, &SoonestResetSelector{}, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "claude"})
	model := "soonest-reset-test-model"
	authIDs := []string{"soonest-reset-auth-a", "soonest-reset-auth-b"}
	registerSchedulerModels(t, "claude", model, authIDs...)
	for _, id := range authIDs {
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: id, Provider: "claude"}); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", id, errRegister)
		}
	}

	now := time.Now()
	weeklyResets := map[string]time.Time{
		"soonest-reset-auth-a": now.Add(5 * 24 * time.Hour),
		"soonest-reset-auth-b": now.Add(2 * 24 * time.Hour),
	}
	for id, weeklyReset := range weeklyResets {
		ctx := internallogging.WithResponseHeadersHolder(context.Background())
		internallogging.SetResponseHeaders(ctx, http.Header{
			"Anthropic-Ratelimit-Unified-7d-Reset": []string{unixSignal(weeklyReset)},
			"Anthropic-Ratelimit-Unified-5h-Reset": []string{unixSignal(now.Add(time.Hour))},
		})
		manager.MarkResult(ctx, Result{AuthID: id, Provider: "claude", Model: model, Success: true})
	}

	for i := 0; i < 3; i++ {
		selected, errSelect := manager.SelectAuth(context.Background(), "claude", model, cliproxyexecutor.Options{})
		if errSelect != nil {
			t.Fatalf("SelectAuth() #%d error = %v", i, errSelect)
		}
		if selected == nil || selected.ID != "soonest-reset-auth-b" {
			t.Fatalf("SelectAuth() #%d auth = %v, want soonest-reset-auth-b", i, selected)
		}
	}
}

func TestManagerSoonestResetProbesCredentialAddedAfterObservation(t *testing.T) {
	t.Parallel()

	manager := NewManager(nil, &SoonestResetSelector{}, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "claude"})
	model := "soonest-reset-probe-test-model"
	observedID, addedID := "soonest-reset-probe-auth-a", "soonest-reset-probe-auth-b"
	registerSchedulerModels(t, "claude", model, observedID, addedID)

	now := time.Now()
	observe := func(id string, weeklyReset time.Time) {
		t.Helper()
		ctx := internallogging.WithResponseHeadersHolder(context.Background())
		internallogging.SetResponseHeaders(ctx, http.Header{
			"Anthropic-Ratelimit-Unified-7d-Reset": []string{unixSignal(weeklyReset)},
			"Anthropic-Ratelimit-Unified-5h-Reset": []string{unixSignal(now.Add(time.Hour))},
		})
		manager.MarkResult(ctx, Result{AuthID: id, Provider: "claude", Model: model, Success: true})
	}
	selectID := func() string {
		t.Helper()
		selected, errSelect := manager.SelectAuth(context.Background(), "claude", model, cliproxyexecutor.Options{})
		if errSelect != nil {
			t.Fatalf("SelectAuth() error = %v", errSelect)
		}
		if selected == nil {
			t.Fatal("SelectAuth() returned nil auth")
		}
		return selected.ID
	}

	if _, errRegister := manager.Register(context.Background(), withOAuthMetadata(&Auth{ID: observedID, Provider: "claude"})); errRegister != nil {
		t.Fatalf("Register(%s) error = %v", observedID, errRegister)
	}
	observe(observedID, now.Add(2*24*time.Hour))
	if _, errRegister := manager.Register(context.Background(), withOAuthMetadata(&Auth{ID: addedID, Provider: "claude"})); errRegister != nil {
		t.Fatalf("Register(%s) error = %v", addedID, errRegister)
	}

	if got := selectID(); got != addedID {
		t.Fatalf("SelectAuth() before probe = %s, want %s", got, addedID)
	}
	observe(addedID, now.Add(5*24*time.Hour))
	if got := selectID(); got != observedID {
		t.Fatalf("SelectAuth() after probe = %s, want %s", got, observedID)
	}
}
