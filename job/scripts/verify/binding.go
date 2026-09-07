package verify

import "fmt"

const (
	CanonicalBinding = "FORGE-OPS-HIGHEND-v1.0.0"
	LegacyBinding    = "FORGE-OPS-HIGHEND/v1.0.0"
)

type Binding struct {
	Family  string
	Version string
}

var forgeHighEndV1 = Binding{
	Family:  "FORGE-OPS-HIGHEND",
	Version: "1.0.0",
}

func ParseBinding(raw string) (Binding, error) {
	switch raw {
	case CanonicalBinding, LegacyBinding:
		return forgeHighEndV1, nil
	default:
		return Binding{}, fmt.Errorf("unsupported FORGE binding %q", raw)
	}
}

func EquivalentBinding(a, b string) bool {
	left, err := ParseBinding(a)
	if err != nil {
		return false
	}
	right, err := ParseBinding(b)
	if err != nil {
		return false
	}
	return left == right
}
