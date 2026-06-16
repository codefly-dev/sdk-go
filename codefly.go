package codefly

import (
	"context"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/wool"
	"os"
	"runtime/debug"
	"strings"
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

	service = os.Getenv("CODEFLY__SERVICE")
	module = os.Getenv("CODEFLY__MODULE")

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
	envs      []string
	envByName = map[string]string{}
)

func LoadEnvironmentVariables() error {
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
		envByName[name] = value
	}
	envs = envs[:0]
	for name, value := range envByName {
		envs = append(envs, name+"="+value)
	}
	return nil
}

func ServiceVersion() string {
	return os.Getenv("CODEFLY__SERVICE_VERSION")
}

func WithFixture(fixture string) bool {
	return os.Getenv("CODEFLY__FIXTURE") == fixture
}
