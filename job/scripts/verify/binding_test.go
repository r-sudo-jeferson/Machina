package verify

import "testing"

func TestParseBindingAcceptsCanonicalAndLegacySerialization(t *testing.T) {
	t.Parallel()

	cases := []string{
		"FORGE-OPS-HIGHEND-v1.0.0",
		"FORGE-OPS-HIGHEND/v1.0.0",
	}

	for _, raw := range cases {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			got, err := ParseBinding(raw)
			if err != nil {
				t.Fatalf("ParseBinding(%q) returned error: %v", raw, err)
			}
			if got.Family != "FORGE-OPS-HIGHEND" {
				t.Fatalf("Family = %q, want %q", got.Family, "FORGE-OPS-HIGHEND")
			}
			if got.Version != "1.0.0" {
				t.Fatalf("Version = %q, want %q", got.Version, "1.0.0")
			}
		})
	}
}

func TestEquivalentBindingTreatsOnlyApprovedSerializationsAsEquivalent(t *testing.T) {
	t.Parallel()

	if !EquivalentBinding("FORGE-OPS-HIGHEND-v1.0.0", "FORGE-OPS-HIGHEND/v1.0.0") {
		t.Fatal("approved binding serializations must be equivalent")
	}
}

func TestParseBindingRejectsUnknownOrDriftedValues(t *testing.T) {
	t.Parallel()

	cases := []string{
		"forge-ops-highend-v1.0.0",
		"FORGE-OPS-HIGHEND-v1.0.1",
		"FORGE-OPS-HIGHEND/v2.0.0",
		"FORGE-OPS-HIGHEND_v1.0.0",
		"FORGE-OPS-HIGHEND-v1.0.*",
		"FORGE-OPS-HIGHEND-v1.0.0-extra",
		"prefix-FORGE-OPS-HIGHEND-v1.0.0",
		"FORGE-OPS-HIGHEND",
		"",
	}

	for _, raw := range cases {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseBinding(raw); err == nil {
				t.Fatalf("ParseBinding(%q) succeeded; want fail-closed error", raw)
			}
		})
	}
}
