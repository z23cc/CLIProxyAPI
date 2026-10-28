package auth

import (
	"testing"
	"time"
)

func metaADRecoverMarkedMetadata(by string) map[string]any {
	return map[string]any{
		"type":            "meta",
		"email":           "user@example.com",
		"disabled":        true,
		"disabled_by":     by,
		"disabled_reason": "mint_rejected",
		"disabled_at":     "2026-10-28T10:00:00Z",
	}
}

func TestMetaAutoDisableRecover_FreshLoginDropsCoreAutoDisable(t *testing.T) {
	target := &Auth{Provider: "meta", Metadata: map[string]any{"type": "meta", "access_token": "new-key"}}
	MergeExistingAuthMetadata(target, metaADRecoverMarkedMetadata("cliproxyapi"))

	if target.Disabled {
		t.Fatal("a fresh login inherited the core auto-disable")
	}
	for _, key := range []string{"disabled", "disabled_by", "disabled_reason", "disabled_at"} {
		if _, ok := target.Metadata[key]; ok {
			t.Fatalf("metadata %q carried over from the auto-disabled credential: %#v", key, target.Metadata)
		}
	}
	if target.Metadata["email"] != "user@example.com" {
		t.Fatalf("unrelated metadata was not carried over: %#v", target.Metadata)
	}
}

func TestMetaAutoDisableRecover_OtherDisablesSurviveLogin(t *testing.T) {
	for name, existing := range map[string]map[string]any{
		"usage_statistics_marker": metaADRecoverMarkedMetadata("usage-statistics"),
		"admin_disable":           {"type": "meta", "disabled": true},
	} {
		t.Run(name, func(t *testing.T) {
			target := &Auth{Provider: "meta", Metadata: map[string]any{"type": "meta", "access_token": "new-key"}}
			MergeExistingAuthMetadata(target, existing)
			if !target.Disabled {
				t.Fatal("a disable that the core did not write was dropped by the login merge")
			}
			if by, ok := existing["disabled_by"]; ok && target.Metadata["disabled_by"] != by {
				t.Fatalf("disabled_by = %#v, want %#v", target.Metadata["disabled_by"], by)
			}
		})
	}
}

func TestMetaAutoDisableRecover_ClearMarkers(t *testing.T) {
	marked := &Auth{Provider: "meta", Metadata: metaADRecoverMarkedMetadata("cliproxyapi")}
	if by, reason, at := MetaAutoDisableMarkers(marked); by != "cliproxyapi" || reason != "mint_rejected" || at != "2026-10-28T10:00:00Z" {
		t.Fatalf("MetaAutoDisableMarkers = %q %q %q", by, reason, at)
	}
	if !ClearMetaAutoDisableMarkers(marked) {
		t.Fatal("ClearMetaAutoDisableMarkers did not report the removal")
	}
	for _, key := range []string{"disabled_by", "disabled_reason", "disabled_at"} {
		if _, ok := marked.Metadata[key]; ok {
			t.Fatalf("marker %q survived: %#v", key, marked.Metadata)
		}
	}
	if by, _, _ := MetaAutoDisableMarkers(marked); by != "" {
		t.Fatalf("markers still reported after clearing: %q", by)
	}

	foreign := &Auth{Provider: "meta", Metadata: metaADRecoverMarkedMetadata("usage-statistics")}
	if ClearMetaAutoDisableMarkers(foreign) {
		t.Fatal("cleared another writer's markers")
	}
	if foreign.Metadata["disabled_by"] != "usage-statistics" || foreign.Metadata["disabled_reason"] != "mint_rejected" {
		t.Fatalf("foreign markers changed: %#v", foreign.Metadata)
	}
}

func TestMetaAutoDisableRecover_ClearKeepsTrackingWithoutMarker(t *testing.T) {
	// Re-enabling an already enabled, pending credential must not drop its tracking:
	// the feature's own block would then be left behind with nothing to lift it.
	auth := &Auth{Provider: "meta", Metadata: map[string]any{"access_token": "key", "dca_token": "dca"}}
	auth.metaAD = metaAutoDisableState{state: "pending", reason: metaADReasonMintRejected, since: time.Now(), cred: metaADFingerprint(auth)}
	if ClearMetaAutoDisableMarkers(auth) {
		t.Fatal("reported a removal without a marker")
	}
	if auth.metaAD.state != "pending" {
		t.Fatalf("tracking dropped: %+v", auth.metaAD)
	}
}
