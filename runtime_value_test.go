package codefly_test

import (
	"testing"

	codefly "github.com/codefly-dev/sdk-go"
)

func TestRuntimeValueReadsTheInjectedValue(t *testing.T) {
	t.Setenv("CODEFLY__MODULE_IDENTITY_PREFIX", "documents")

	value, ok := codefly.RuntimeValue("MODULE_IDENTITY_PREFIX")
	if !ok {
		t.Fatal("RuntimeValue reported no injected value")
	}
	if value != "documents" {
		t.Fatalf("RuntimeValue = %q, want %q", value, "documents")
	}
}

// A caller names the value, not the carrier, so the spellings a caller may
// reasonably use must all reach the same injected value.
func TestRuntimeValueNormalizesTheName(t *testing.T) {
	t.Setenv("CODEFLY__MODULE_IDENTITY_SECRET", "s3cret")

	for _, name := range []string{"MODULE_IDENTITY_SECRET", "module_identity_secret", "module-identity-secret", "  Module-Identity-Secret  "} {
		value, ok := codefly.RuntimeValue(name)
		if !ok || value != "s3cret" {
			t.Fatalf("RuntimeValue(%q) = (%q, %v), want (%q, true)", name, value, ok, "s3cret")
		}
	}
}

func TestRuntimeValueReportsAbsent(t *testing.T) {
	if value, ok := codefly.RuntimeValue("MODULE_IDENTITY_UNSET"); ok {
		t.Fatalf("RuntimeValue reported %q for a value the runtime never injected", value)
	}
	if value, ok := codefly.RuntimeValue("   "); ok {
		t.Fatalf("RuntimeValue reported %q for an unnamed value", value)
	}
}

// A composition that templates an unset variable ships the name with an empty
// value. Reporting that as present would let it shadow whatever configuration
// custody the caller falls back to.
func TestRuntimeValueTreatsBlankAsAbsent(t *testing.T) {
	t.Setenv("CODEFLY__MODULE_IDENTITY_PREFIX", "")
	if value, ok := codefly.RuntimeValue("MODULE_IDENTITY_PREFIX"); ok {
		t.Fatalf("RuntimeValue reported %q for an empty carrier", value)
	}

	t.Setenv("CODEFLY__MODULE_IDENTITY_PREFIX", "   \n")
	if value, ok := codefly.RuntimeValue("MODULE_IDENTITY_PREFIX"); ok {
		t.Fatalf("RuntimeValue reported %q for a whitespace-only carrier", value)
	}
}

func TestRuntimeValueTrimsTheInjectedValue(t *testing.T) {
	t.Setenv("CODEFLY__MODULE_IDENTITY_PREFIX", "  documents\n")

	value, ok := codefly.RuntimeValue("module-identity-prefix")
	if !ok {
		t.Fatal("RuntimeValue reported no injected value")
	}
	if value != "documents" {
		t.Fatalf("RuntimeValue = %q, want %q", value, "documents")
	}
}
