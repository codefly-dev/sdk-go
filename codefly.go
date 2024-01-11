package codefly

import (
	"context"
	"fmt"
	"github.com/codefly-dev/core/configurations"
	"github.com/codefly-dev/core/wool"
	"os"
	"path"
	"runtime/debug"
	"strings"
)

var environmentManager *configurations.EnvironmentVariableManager
var networkOverrides map[string]string

func CatchPanic(ctx context.Context) {
	w := wool.Get(ctx).In("codefly.CatchPanic")
	if r := recover(); r != nil {
		w.Error("Caught panic: %s", wool.Field("panic", r), wool.Field("stack", string(debug.Stack())))
		os.Exit(1)
	}
}

func GetLogLevel() wool.Loglevel {
	if os.Getenv("CODEFLY_SDK__LOGLEVEL") == "debug" {
		return wool.DEBUG
	} else if os.Getenv("CODEFLY_SDK__LOGLEVEL") == "trace" {
		return wool.TRACE
	}
	return wool.INFO
}

func Init(ctx context.Context) (*wool.Provider, error) {
	if root == "" {
		root, _ = os.Getwd()
	}

	// For logging before we get the service
	provider := wool.New(ctx, configurations.CLI.AsResource()).WithConsole(GetLogLevel())
	ctx = provider.Inject(ctx)

	err := LoadService(ctx)
	if err != nil {
		return nil, err
	}

	// Now update the provider
	provider = wool.New(ctx, service.Identity().AsResource()).WithConsole(GetLogLevel())
	ctx = provider.Inject(ctx)

	err = LoadFromEnvironmentVariables(ctx)
	if err != nil {
		return nil, err
	}

	networkOverrides = make(map[string]string)

	err = LoadOverrides(ctx)
	if err != nil {
		return nil, err
	}
	return provider, nil
}

var root string
var service *configurations.Service

func WithRoot(dir string) {
	root = dir
}

func LoadService(ctx context.Context) error {
	svc, err := configurations.LoadServiceFromDirUnsafe(ctx, root)
	if err != nil {
		return err
	}
	service = svc
	return nil
}

func Version() string {
	if service == nil {
		return "unknown"
	}
	return service.Version
}

func LoadFromEnvironmentVariables(ctx context.Context) error {
	environmentManager = configurations.NewEnvironmentVariableManager()
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "CODEFLY") {
			continue
		}
		environmentManager.Add(env)
	}
	return nil
}

type EndpointOverride struct {
	Name     string
	Override string
}

type Configuration struct {
	Endpoints []EndpointOverride
}

func LoadOverrides(ctx context.Context) error {
	if os.Getenv("CODEFLY_SDK__WITHOVERRIDE") != "true" {
		return nil
	}
	w := wool.Get(ctx).In("codefly.LoadOverrides")
	dir, err := configurations.SolveDir(root)
	if err != nil {
		return w.Wrapf(err, "cannot solve dir")
	}
	config, err := configurations.LoadFromPath[Configuration](ctx, path.Join(dir, ".codefly.yaml"))
	if err != nil {
		return w.Wrapf(err, "cannot load override configuration")
	}
	for _, endpoint := range config.Endpoints {
		w.Info("overloading endpoint", wool.Field("endpoint", endpoint), wool.Field("override", endpoint.Override))
		networkOverrides[endpoint.Name] = endpoint.Override
	}
	return nil
}

func GetEndpoint(ctx context.Context, unique string) (*configurations.EndpointInstance, error) {
	if strings.HasPrefix(unique, "self") {
		if service == nil {
			return nil, fmt.Errorf("self only allowed when a codefly service configuration is found")
		}
		unique = strings.Replace(unique, "self", service.Unique(), 1)
	}
	if override, ok := networkOverrides[unique]; ok {
		endpoint, err := configurations.ParseEndpoint(unique)
		if err != nil {
			return nil, err
		}
		return &configurations.EndpointInstance{Endpoint: endpoint, Addresses: []string{override}}, nil
	}
	return environmentManager.GetEndpoint(ctx, unique)
}

func GetProjectProvider(ctx context.Context, key string) (string, error) {
	return environmentManager.GetProjectProvider(ctx, key)
}

func GetServiceProvider(ctx context.Context, unique string, key string) (string, error) {
	return environmentManager.GetServiceProvider(ctx, unique, key)
}
