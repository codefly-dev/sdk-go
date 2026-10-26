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
	wotel "github.com/codefly-dev/core/wool/otel"
	"github.com/codefly-dev/sdk-go/internal/enclosing"
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
	if err := LoadEnvironmentVariables(); err != nil {
		return nil, err
	}
	identity := strings.TrimSpace(os.Getenv(resources.ModulePrefix))
	if err := pinConsumerIdentity(identity); err != nil {
		return nil, err
	}
	// For logging before we get the runningService
	var provider *wool.Provider

	service = os.Getenv(resources.ServicePrefix)
	module = identity

	// Now update the provider
	id := resources.ServiceIdentity{Name: service, Module: module}
	provider = wool.New(ctx, id.AsResource()).WithConsole(GetLogLevel())

	// Keep the provider-injected context so Context() can hand it back. The
	// previous code injected into a local `ctx` and discarded it, so callers
	// that kept their own context saw no provider and silently fell back to the
	// default console logger (dropping the configured level + service identity).
	runningCtx = provider.Inject(ctx)

	enableTelemetryExport(runningCtx, id)

	return provider, nil
}

// telemetry is the trace exporter Init enabled, for ShutdownTelemetry to flush.
var telemetry *wotel.Provider

// enableTelemetryExport turns on the OTLP trace exporter when the process was
// handed somewhere to export to. Codefly delivers OTEL_EXPORTER_OTLP_ENDPOINT
// (a URL whose scheme fixes the transport), OTEL_SERVICE_NAME and
// OTEL_RESOURCE_ATTRIBUTES to every service it runs or renders, from the
// environment's `telemetry:` block; a process started with none exports nothing
// and says nothing. A service never declares a group or dials an address for
// this: wool/otel reads the specification's variables and this is the only
// call site. An exporter that cannot be built is reported, not fatal — a
// telemetry outage must not stop a service from serving — and the reason is
// in the service's own log where an operator looks first.
func enableTelemetryExport(ctx context.Context, id resources.ServiceIdentity) {
	if strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")) == "" {
		return
	}
	name := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME"))
	if name == "" {
		name = id.Module + "/" + id.Name
	}
	provider, err := wotel.Enable(wotel.WithServiceName(name))
	w := wool.Get(ctx).In("codefly.Init")
	if err != nil {
		w.Warn("telemetry export is configured but its exporter could not be built; traces stay in-process",
			wool.Field("endpoint", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")), wool.ErrField(err))
		return
	}
	telemetry = provider
	w.Info("telemetry export enabled", wool.Field("endpoint", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")), wool.Field("service", name))
}

// ShutdownTelemetry flushes and stops the trace exporter Init enabled, so the
// last spans of a stopping process reach the collector. A process that enabled
// none returns nil.
func ShutdownTelemetry(ctx context.Context) error {
	if telemetry == nil {
		return nil
	}
	err := telemetry.Shutdown(ctx)
	telemetry = nil
	return err
}

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
	// A value delivered by file is part of the snapshot like any other: its
	// carrier names the file, and the value is what the file holds.
	carried, err := fileCarriedValues(os.Environ())
	if err != nil {
		return err
	}
	for name, value := range carried {
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
		environment := localConfigurationEnvironmentName()
		envs, err := resources.ConfigurationAsEnvironmentVariables(configuration, environment, false)
		if err != nil {
			return err
		}
		secrets, err := resources.ConfigurationAsEnvironmentVariables(configuration, environment, true)
		if err != nil {
			return err
		}
		envs = append(envs, secrets...)
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

// carrierNames lists the name of every carrier the lookup sources hold: the
// snapshot (process values, file-carried values and injected values) and the
// live process environment, where a file carrier is listed under the key it
// carries. A listing accessor enumerates these names and then reads each one
// through the ordinary lookup, so it never answers from a source the lookup
// would not read.
func carrierNames() []string {
	names := map[string]struct{}{}
	for _, entry := range codeflyEnvironmentVariables() {
		name, _, _ := strings.Cut(entry, "=")
		names[name] = struct{}{}
	}
	for _, entry := range os.Environ() {
		name, _, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		if resources.IsFileCarrierKey(name) {
			name = resources.CarriedKey(name)
		}
		names[name] = struct{}{}
	}
	listed := make([]string, 0, len(names))
	for name := range names {
		listed = append(listed, name)
	}
	sort.Strings(listed)
	return listed
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

// The fixture API moved to the sdk-go/fixture package: it was the only thing in
// this root package that needed core/composition, and composition carries a
// GitHub release resolver, so every service importing codefly for its own
// address linked a GitHub API client it never calls. Use fixture.Selected().

// Environment returns the Codefly environment selected for this process. The
// representation is owned by the SDK; product code must not read its carrier.
func Environment() string {
	return os.Getenv(resources.EnvironmentPrefix)
}

// Workspace returns the Codefly workspace identity for the current process.
// A runtime-injected identity is authoritative. Local tools that are not
// launched as a service fall back to the name the enclosing workspace file
// declares — read, not composed, so a workspace whose imports only the CLI can
// resolve still names itself — keeping product code independent from Codefly's
// environment-variable carriers.
func Workspace(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	name, err := enclosing.Name(ctx)
	if err != nil {
		return "", fmt.Errorf("resolve Codefly workspace: %w", err)
	}
	if name == "" {
		return "", fmt.Errorf("resolve Codefly workspace: no enclosing workspace")
	}
	return name, nil
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
