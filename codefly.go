package codefly

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"sync"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
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
	environmentVariablesMu       sync.RWMutex
	processEnvironmentVariables  map[string]string
	injectedConfigurationValues  map[string]string
	injectedEndpointValues       map[string]string
	environmentVariablesSnapshot []string
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
	environmentVariablesMu.Lock()
	processEnvironmentVariables = values
	rebuildEnvironmentSnapshotLocked()
	environmentVariablesMu.Unlock()
	return nil
}

// InjectConfigurations replaces the SDK's in-process configuration carrier
// without mutating the process environment. This is the library boundary for
// an embedded Codefly flow: resolved configuration enters the same immutable
// snapshot queried by For. Calling it with no configurations clears the prior
// injected configuration values.
func InjectConfigurations(configurations ...*basev0.Configuration) error {
	values := make(map[string]string)
	for _, configuration := range configurations {
		if configuration == nil {
			continue
		}
		if strings.TrimSpace(configuration.Origin) == "" {
			return errors.New("inject configuration: origin is required")
		}
		for _, information := range configuration.Infos {
			if information == nil || strings.TrimSpace(information.Name) == "" {
				return fmt.Errorf("inject configuration %s: information name is required", configuration.Origin)
			}
			for _, value := range information.ConfigurationValues {
				if value == nil || strings.TrimSpace(value.Key) == "" {
					return fmt.Errorf("inject configuration %s/%s: value key is required", configuration.Origin, information.Name)
				}
			}
		}
		envs := resources.ConfigurationAsEnvironmentVariables(configuration, false)
		envs = append(envs, resources.ConfigurationAsEnvironmentVariables(configuration, true)...)
		for _, env := range envs {
			if env == nil || strings.TrimSpace(env.Key) == "" {
				continue
			}
			values[env.Key] = env.ValueAsString()
		}
	}

	environmentVariablesMu.Lock()
	injectedConfigurationValues = values
	rebuildEnvironmentSnapshotLocked()
	environmentVariablesMu.Unlock()
	return nil
}

// InjectEndpoints replaces the SDK's in-process endpoint carrier without
// mutating the process environment. Calling it with no endpoints clears the
// prior injected endpoint values. Invalid endpoint access is rejected before
// the live snapshot changes.
func InjectEndpoints(endpoints ...*resources.EndpointAccess) error {
	values := make(map[string]string)
	for index, endpoint := range endpoints {
		if endpoint == nil || endpoint.Endpoint == nil || endpoint.NetworkInstance == nil {
			return fmt.Errorf("inject endpoint %d: endpoint and network instance are required", index)
		}
		if strings.TrimSpace(endpoint.Endpoint.Module) == "" ||
			strings.TrimSpace(endpoint.Endpoint.Service) == "" ||
			strings.TrimSpace(endpoint.Endpoint.Name) == "" ||
			strings.TrimSpace(endpoint.Endpoint.Api) == "" ||
			strings.TrimSpace(endpoint.NetworkInstance.Address) == "" {
			return fmt.Errorf("inject endpoint %d: module, service, name, api, and address are required", index)
		}
		env := resources.EndpointAsEnvironmentVariable(endpoint)
		values[env.Key] = env.ValueAsString()
	}

	environmentVariablesMu.Lock()
	injectedEndpointValues = values
	rebuildEnvironmentSnapshotLocked()
	environmentVariablesMu.Unlock()
	return nil
}

func rebuildEnvironmentSnapshotLocked() {
	size := len(processEnvironmentVariables) + len(injectedConfigurationValues) + len(injectedEndpointValues)
	values := make(map[string]string, size)
	for name, value := range processEnvironmentVariables {
		values[name] = value
	}
	for name, value := range injectedConfigurationValues {
		values[name] = value
	}
	for name, value := range injectedEndpointValues {
		values[name] = value
	}
	snapshot := make([]string, 0, len(values))
	for name, value := range values {
		snapshot = append(snapshot, name+"="+value)
	}
	sort.Strings(snapshot)
	environmentVariablesSnapshot = snapshot
}

func codeflyEnvironmentVariables() []string {
	environmentVariablesMu.RLock()
	defer environmentVariablesMu.RUnlock()
	return append([]string(nil), environmentVariablesSnapshot...)
}

func injectedEnvironmentValue(name string) (string, bool) {
	environmentVariablesMu.RLock()
	defer environmentVariablesMu.RUnlock()
	if value, ok := injectedConfigurationValues[name]; ok && value != "" {
		return value, true
	}
	if value, ok := injectedEndpointValues[name]; ok && value != "" {
		return value, true
	}
	return "", false
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

// Workspace returns the Codefly workspace identity for the current process.
// A runtime-injected identity is authoritative. Local tools that are not
// launched as a service fall back to the enclosing workspace resource, keeping
// product code independent from Codefly's environment-variable carriers.
func Workspace(ctx context.Context) (string, error) {
	if name := strings.TrimSpace(os.Getenv(resources.WorkspacePrefix)); name != "" {
		return name, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	workspace, err := resources.FindWorkspaceUp(ctx)
	if err != nil {
		return "", fmt.Errorf("resolve Codefly workspace: %w", err)
	}
	if workspace == nil || strings.TrimSpace(workspace.Name) == "" {
		return "", fmt.Errorf("resolve Codefly workspace: no enclosing workspace")
	}
	return workspace.Name, nil
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
