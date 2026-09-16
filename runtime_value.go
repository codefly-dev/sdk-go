package codefly

import (
	"os"
	"strings"
)

// runtimeValuePrefix is the carrier namespace the runtime injects process
// values under. It is spelled here, in the SDK, so product code never spells
// it: the encoding is an SDK/runtime implementation detail.
const runtimeValuePrefix = "CODEFLY__"

// RuntimeValue returns one value the Codefly runtime injects directly into a
// process, addressed by its name — "MODULE_IDENTITY_PREFIX", not the carrier
// that transports it. The name is matched case-insensitively, and '-' is
// accepted for '_', the same normalization the workspace accessors apply.
//
// It reports false when the runtime injected nothing, or injected only
// whitespace: a composition that templates an unset variable ships the name
// with an empty value, and that must not shadow the configuration custody a
// caller falls back to.
//
// This is the accessor for values the runtime hands a process directly.
// Configuration and secrets provisioned through a workspace or service group
// have typed accessors on For and belong there.
func RuntimeValue(name string) (string, bool) {
	key := runtimeValueKey(name)
	if key == "" {
		return "", false
	}
	value, ok := injectedEnvironmentValue(key)
	if !ok {
		value = os.Getenv(key)
	}
	if value = strings.TrimSpace(value); value == "" {
		return "", false
	}
	return value, true
}

func runtimeValueKey(name string) string {
	normalized := strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(name)), "-", "_")
	if normalized == "" {
		return ""
	}
	return runtimeValuePrefix + normalized
}
