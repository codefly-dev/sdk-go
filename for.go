package codefly

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/codefly-dev/core/configurations"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/network"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/standards"
	"github.com/codefly-dev/core/wool"
)

type Query struct {
	module             string
	service            string
	endpointName       string
	endpointApi        string
	ctx                context.Context
	withDefaultNetwork bool
	namingScope        string
}

func For(ctx context.Context) *Query {
	q := &Query{ctx: ctx}
	// The process environment is the runtime authority. Falling back to the
	// values captured by Init preserves callers that construct a query after
	// startup, while the direct read also makes early queries and runtime
	// reinjection behave correctly.
	q.service = os.Getenv(resources.ServicePrefix)
	if q.service == "" {
		q.service = service
	}
	q.module = os.Getenv(resources.ModulePrefix)
	if q.module == "" {
		q.module = module
	}
	return q
}

func (q *Query) Service(s string) *Query {
	q.service = s
	return q
}

func (q *Query) Module(s string) *Query {
	q.module = s
	return q
}

func (q *Query) API(name string) *Query {
	q.endpointApi = name
	return q
}

// Endpoint sets the endpoint name independently from the API type.
// Use when the endpoint name differs from the API protocol.
// Example: codefly.For(ctx).Service("neo4j").Endpoint("bolt").API("tcp")
func (q *Query) Endpoint(name string) *Query {
	q.endpointName = name
	return q
}

func (q *Query) Normalize() {
	if q.endpointName == "" && q.endpointApi != "" {
		q.endpointName = q.endpointApi
	}
}

func (q *Query) WithDefaultNetwork() *Query {
	q.withDefaultNetwork = true
	return q
}

// NamingScope selects the same advanced local port namespace used by
// `codefly run --naming-scope`. Leave empty for the normal interactive
// workspace.
func (q *Query) NamingScope(scope string) *Query {
	q.namingScope = strings.TrimSpace(scope)
	return q
}

func (q *Query) NetworkInstance() *resources.NetworkInstance {
	instance, err := q.ResolveNetworkInstance()
	if err == nil {
		return instance
	}
	w := wool.Get(q.ctx).In("NetworkInstance")
	if q.withDefaultNetwork {
		w.Warn("Cannot find network instance, returning default", wool.Field("error", err))
		return resources.DefaultNetworkInstance(q.endpointApi)
	}
	return nil
}

// ResolveNetworkInstance returns one typed endpoint or a diagnostic error.
//
// Runtime-injected endpoint capabilities always win. In Codefly LOCAL (and
// before an environment is explicitly selected), the SDK falls back to the
// workspace's deterministic native endpoint map. This lets independently
// loaded agents use the same address as `codefly endpoint` without parsing
// Codefly environment carriers or shelling out to the CLI.
func (q *Query) ResolveNetworkInstance() (*resources.NetworkInstance, error) {
	q.Normalize()
	info := &resources.EndpointInformation{
		Module:  q.module,
		Service: q.service,
		API:     q.endpointApi,
		Name:    q.endpointName,
	}
	instance, err := resources.FindNetworkInstanceInEnvironmentVariables(q.ctx, info, codeflyEnvironmentVariables())
	if err == nil {
		return instance, nil
	}
	if Environment() == "" || IsLocal() {
		local, localErr := q.resolveLocalNetworkInstance()
		if localErr == nil {
			return local, nil
		}
		err = fmt.Errorf("runtime endpoint unavailable (%v); local endpoint unavailable (%w)", err, localErr)
	}
	if q.withDefaultNetwork {
		return resources.DefaultNetworkInstance(q.endpointApi), nil
	}
	return nil, err
}

func (q *Query) resolveLocalNetworkInstance() (*resources.NetworkInstance, error) {
	if strings.TrimSpace(q.module) == "" || strings.TrimSpace(q.service) == "" {
		return nil, errors.New("module and service are required for local endpoint resolution")
	}
	workspace, err := resources.FindWorkspaceUp(q.ctx)
	if err != nil {
		return nil, err
	}
	if workspace == nil {
		return nil, errors.New("workspace not found")
	}
	module, err := workspace.LoadModuleFromName(q.ctx, q.module)
	if err != nil {
		return nil, err
	}
	service, err := module.LoadServiceFromName(q.ctx, q.service)
	if err != nil {
		return nil, err
	}
	var selected *resources.Endpoint
	for _, endpoint := range service.Endpoints {
		api := endpoint.API
		if api == "" && standards.IsSupportedAPI(endpoint.Name) == nil {
			api = endpoint.Name
		}
		if q.endpointName != "" && !resources.Match(endpoint.Name, q.endpointName) {
			continue
		}
		if q.endpointApi != "" && !resources.Match(api, q.endpointApi) {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf(
				"multiple endpoints match %s/%s name=%q api=%q",
				q.module,
				q.service,
				q.endpointName,
				q.endpointApi,
			)
		}
		selected = endpoint
	}
	if selected == nil {
		return nil, fmt.Errorf(
			"no endpoint matches %s/%s name=%q api=%q",
			q.module,
			q.service,
			q.endpointName,
			q.endpointApi,
		)
	}
	if selected.Visibility == resources.VisibilityExternal {
		return nil, errors.New("external endpoint cannot be resolved from the local native map")
	}
	api := selected.API
	if api == "" && standards.IsSupportedAPI(selected.Name) == nil {
		api = selected.Name
	}
	if standards.IsSupportedAPI(api) != nil {
		return nil, fmt.Errorf("endpoint API %q is not supported by the local native map", api)
	}
	native := network.NativeFor(
		q.ctx,
		workspace.Name,
		q.module,
		q.service,
		q.namingScope,
		&basev0.Endpoint{
			Name:       selected.Name,
			Api:        api,
			Visibility: selected.Visibility,
		},
	)
	if native.Port > uint32(^uint16(0)) {
		return nil, fmt.Errorf("resolved endpoint port %d exceeds uint16", native.Port)
	}
	return &resources.NetworkInstance{
		Port:     uint16(native.Port),
		Hostname: native.Hostname,
		Host:     native.Host,
		Address:  native.Address,
	}, nil
}

func (q *Query) Configuration(key string, name string) (string, error) {
	q.Normalize()
	unique := resources.ServiceUnique(q.module, q.service)
	envKey := resources.ServiceConfigurationKeyFromUnique(unique, key, name)
	legacyKey := fmt.Sprintf("%s__%s__%s",
		resources.ServiceConfigurationEnvironmentKeyPrefixFromUnique(unique),
		strings.ToUpper(key), strings.ToUpper(name))
	if value, ok := runtimeServiceConfigurationValue(q.ctx, envKey, legacyKey, strings.ReplaceAll(legacyKey, "-", "_")); ok {
		return value, nil
	}
	return q.localConfigurationValue(key, name, false)
}

func (q *Query) Secret(key string, name string) (string, error) {
	q.Normalize()
	unique := resources.ServiceUnique(q.module, q.service)
	envKey := resources.ServiceSecretConfigurationKeyFromUnique(unique, key, name)
	legacyKey := fmt.Sprintf("%s__%s__%s",
		resources.ServiceSecretConfigurationEnvironmentKeyPrefixFromUnique(unique),
		strings.ToUpper(key), strings.ToUpper(name))
	if value, ok := runtimeServiceConfigurationValue(q.ctx, envKey, legacyKey, strings.ReplaceAll(legacyKey, "-", "_")); ok {
		return value, nil
	}
	return q.localConfigurationValue(key, name, true)
}

func runtimeServiceConfigurationValue(ctx context.Context, candidates ...string) (string, bool) {
	// Capability names historically preserved '-' while released runtime
	// agents normalize it to '_'. Prefer the current canonical spelling, then
	// accept the legacy carrier so SDK users remain independent of agent version.
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		if value, ok := os.LookupEnv(candidate); ok && value != "" {
			return value, true
		}
		if value, err := resources.FindValueInEnvironmentVariables(ctx, candidate, codeflyEnvironmentVariables()); err == nil && value != "" {
			return value, true
		}
	}
	return "", false
}

// WorkspaceConfiguration returns one non-secret workspace configuration value.
// Product services must use this API instead of depending on Codefly's environment
// variable encoding, which is an SDK/runtime implementation detail.
func (q *Query) WorkspaceConfiguration(name string, key string) (string, error) {
	return q.workspaceConfigurationValue(resources.WorkspaceConfigurationPrefix, name, key)
}

// WorkspaceSecret returns one secret workspace configuration value without
// exposing Codefly's environment variable encoding to the caller.
func (q *Query) WorkspaceSecret(name string, key string) (string, error) {
	return q.workspaceConfigurationValue(resources.WorkspaceSecretConfigurationPrefix, name, key)
}

// WorkspaceValue resolves a workspace value from the public namespace first,
// then the secret namespace. It is intended for settings whose sensitivity is
// deployment-defined while preserving a single SDK-only lookup boundary.
func (q *Query) WorkspaceValue(name string, key string) (string, error) {
	if value, err := q.WorkspaceConfiguration(name, key); err == nil && value != "" {
		return value, nil
	}
	if value, err := q.WorkspaceSecret(name, key); err == nil && value != "" {
		return value, nil
	}
	return "", wool.Get(q.ctx).In("WorkspaceValue").NewError("no workspace configuration value for %s/%s", name, key)
}

func (q *Query) workspaceConfigurationValue(prefix string, name string, key string) (string, error) {
	// Runtime configuration names historically preserved '-' while newer core
	// emitters normalize it to '_'. Exact wins; normalized is compatibility.
	exact := strings.ToUpper(name)
	normalized := normalizeWorkspaceEnvironmentKey(name)
	for _, candidate := range []string{exact, normalized} {
		envKey := fmt.Sprintf("%s__%s__%s", prefix, candidate, normalizeWorkspaceEnvironmentKey(key))
		if value, ok := os.LookupEnv(envKey); ok && value != "" {
			return value, nil
		}
		if value, err := resources.FindValueInEnvironmentVariables(q.ctx, envKey, codeflyEnvironmentVariables()); err == nil && value != "" {
			return value, nil
		}
		if exact == normalized {
			break
		}
	}
	return "", wool.Get(q.ctx).In("WorkspaceConfiguration").NewError("no workspace configuration value for %s/%s", name, key)
}

func normalizeWorkspaceEnvironmentKey(value string) string {
	return strings.ReplaceAll(strings.ToUpper(value), "-", "_")
}

func (q *Query) localConfigurationValue(infoName string, key string, secret bool) (string, error) {
	w := wool.Get(q.ctx).In("LocalConfigurationValue")
	if q.service == "" {
		return "", w.NewError("service is not set")
	}
	workspace, err := resources.FindWorkspaceUp(q.ctx)
	if err != nil {
		return "", err
	}
	if workspace == nil {
		return "", w.NewError("workspace not found")
	}

	var svc *resources.Service
	if q.module != "" {
		mod, err := workspace.LoadModuleFromName(q.ctx, q.module)
		if err != nil {
			return "", err
		}
		svc, err = mod.LoadServiceFromName(q.ctx, q.service)
		if err != nil {
			return "", err
		}
	} else {
		var err error
		svc, _, err = workspace.FindUniqueModuleServiceByName(q.ctx, q.service)
		if err != nil {
			return "", err
		}
	}

	envName := localConfigurationEnvironmentName()
	dir := filepath.Join(svc.Dir(), "configurations", envName)
	infos, err := configurations.LoadConfigurationInformationsFromFiles(q.ctx, dir)
	if err != nil {
		return "", err
	}
	for _, info := range infos {
		if !resources.Match(info.Name, infoName) {
			continue
		}
		for _, value := range info.ConfigurationValues {
			if resources.Match(value.Key, key) && value.Secret == secret {
				return value.Value, nil
			}
		}
	}
	kind := "configuration"
	if secret {
		kind = "secret"
	}
	return "", w.NewError("no %s value for %s/%s in service %s (env=%s)",
		kind, infoName, key, q.service, envName)
}

func localConfigurationEnvironmentName() string {
	if env := os.Getenv(resources.EnvironmentPrefix); env != "" {
		return env
	}
	return resources.LocalEnvironment().Name
}
