package codefly

import (
	"context"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"sync"

	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/wool"
)

var service string
var module string

func CatchPanic(ctx context.Context) {
	w := wool.Get(ctx).In("codefly.CatchPanic")
	if r := recover(); r != nil {
		w.Error("Caught panic", wool.Field("panic", r), wool.Field("stack", string(debug.Stack())))
		os.Exit(1)
	}
}

func GetLogLevel() wool.Loglevel {
	switch strings.ToLower(os.Getenv("CODEFLY__SDK__LOGLEVEL")) {
	case "debug":
		return wool.DEBUG
	case "trace":
		return wool.TRACE
	default:
		return wool.INFO
	}
}

func Init(ctx context.Context) (*wool.Provider, error) {
	var err error
	root, err = os.Getwd()
	if err != nil {
		return nil, err
	}

	err = LoadEnvironmentVariables()

	if err != nil {
		return nil, err
	}
	// For logging before we get the runningService
	var provider *wool.Provider

	service = os.Getenv(resources.ServicePrefix)
	module = os.Getenv(resources.ModulePrefix)

	// Now update the provider
	id := resources.ServiceIdentity{Name: service, Module: module}
	provider = wool.New(ctx, id.AsResource()).WithConsole(GetLogLevel())

	// Keep the provider-injected context so Context() can hand it back. The
	// previous code injected into a local `ctx` and discarded it, so callers
	// that kept their own context saw no provider and silently fell back to the
	// default console logger (dropping the configured level + service identity).
	runningCtx = provider.Inject(ctx)

	return provider, nil
}

var root string
var runningCtx context.Context

// Context returns the provider-injected context built by Init (so wool.Get sees
// the SDK provider), or context.Background() before Init has run.
func Context() context.Context {
	if runningCtx == nil {
		return context.Background()
	}
	return runningCtx
}

var (
	environmentVariablesMu sync.RWMutex
	environmentVariables   []string
)

func LoadEnvironmentVariables() error {
	// Build a new immutable snapshot so a runtime reload cannot retain a carrier
	// removed from the process environment or race with concurrent SDK queries.
	values := make(map[string]string)
	for _, env := range os.Environ() {
		// Use the full "CODEFLY__" prefix: a bare "CODEFLY" also matched
		// unrelated variables like CODEFLYFOO and widened the lookup surface.
		if !strings.HasPrefix(env, "CODEFLY__") {
			continue
		}
		name, value, found := strings.Cut(env, "=")
		if !found {
			continue
		}
		// Dedupe by NAME (latest value wins). Keying on the whole "KEY=value"
		// string meant a reload appended "KEY=new" after "KEY=old"; the
		// first-match lookups then returned the stale value forever.
		values[name] = value
	}
	snapshot := make([]string, 0, len(values))
	for name, value := range values {
		snapshot = append(snapshot, name+"="+value)
	}
	sort.Strings(snapshot)

	environmentVariablesMu.Lock()
	environmentVariables = snapshot
	environmentVariablesMu.Unlock()
	return nil
}

func codeflyEnvironmentVariables() []string {
	environmentVariablesMu.RLock()
	defer environmentVariablesMu.RUnlock()
	return append([]string(nil), environmentVariables...)
}

func ServiceVersion() string {
	return os.Getenv(resources.VersionPrefix)
}

// Fixture returns the fixture selected by the Codefly runtime. Product code
// must not depend on the runtime's environment-variable representation.
func Fixture() string {
	return os.Getenv(resources.FixturePrefix)
}

func WithFixture(fixture string) bool {
	return resources.Match(Fixture(), fixture)
}

// Environment returns the Codefly environment selected for this process. The
// representation is owned by the SDK; product code must not read its carrier.
func Environment() string {
	return os.Getenv(resources.EnvironmentPrefix)
}

// IsLocal reports whether the current Codefly environment is local.
func IsLocal() bool {
	return resources.Match(Environment(), resources.LocalEnvironment().Name)
}

// ScopedAuthSecret returns the host-issued plugin authentication secret. This
// legacy carrier remains encapsulated here until scoped auth moves to a typed
// capability; product code must not read it directly.
func ScopedAuthSecret() string {
	return os.Getenv(scopedAuthSecretEnvironmentKey)
}

const scopedAuthSecretEnvironmentKey = "CODEFLY_SCOPED_AUTH_SECRET"
