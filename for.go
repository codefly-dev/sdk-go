package codefly

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/codefly-dev/core/configurations"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/wool"
)

type Query struct {
	module             string
	service            string
	endpointName       string
	endpointApi        string
	ctx                context.Context
	withDefaultNetwork bool
}

func For(ctx context.Context) *Query {
	q := &Query{ctx: ctx}
	q.service = service
	q.module = module
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

func (q *Query) NetworkInstance() *resources.NetworkInstance {
	w := wool.Get(q.ctx).In("NetworkInstance")
	q.Normalize()
	info := &resources.EndpointInformation{
		Module:  q.module,
		Service: q.service,
		API:     q.endpointApi,
		Name:    q.endpointName,
	}
	instance, err := resources.FindNetworkInstanceInEnvironmentVariables(q.ctx, info, codeflyEnvironmentVariables())
	if err != nil {
		if q.withDefaultNetwork {
			w.Warn("Cannot find network instance, returning default", wool.Field("info", info), wool.Field("error", err))
			return resources.DefaultNetworkInstance(q.endpointApi)
		}
		return nil
	}
	return instance
}

func (q *Query) Configuration(key string, name string) (string, error) {
	q.Normalize()
	unique := resources.ServiceUnique(q.module, q.service)
	envKey := resources.ServiceConfigurationKeyFromUnique(unique, key, name)
	if value, err := resources.FindValueInEnvironmentVariables(q.ctx, envKey, codeflyEnvironmentVariables()); err == nil {
		return value, nil
	}
	return q.localConfigurationValue(key, name, false)
}

func (q *Query) Secret(key string, name string) (string, error) {
	q.Normalize()
	unique := resources.ServiceUnique(q.module, q.service)
	envKey := resources.ServiceSecretConfigurationKeyFromUnique(unique, key, name)
	if value, err := resources.FindValueInEnvironmentVariables(q.ctx, envKey, codeflyEnvironmentVariables()); err == nil {
		return value, nil
	}
	return q.localConfigurationValue(key, name, true)
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
