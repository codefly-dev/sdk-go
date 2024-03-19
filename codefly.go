package codefly

import (
	"context"
	"fmt"
	"github.com/codefly-dev/core/configurations"
	"github.com/codefly-dev/core/shared"
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
		w.Error("Caught panic", wool.Field("panic", r), wool.Field("stack", string(debug.Stack())))
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

func LoadEnvironmentVariables(ctx context.Context) error {
	err := LoadFromEnvironmentVariables(ctx)
	if err != nil {
		return err
	}

	return nil
}

func LoadOverrideIfNeeded(ctx context.Context) error {
	networkOverrides = make(map[string]string)
	if os.Getenv("CODEFLY_SDK__WITHOVERRIDE") == "true" {
		err := LoadOverrides(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

func init() {
	_, err := Init(context.Background())
	if err != nil {
		fmt.Println("Cannot initialize codefly", err)
	}
}

func Init(ctx context.Context) (*wool.Provider, error) {
	var err error
	root, err = os.Getwd()
	if err != nil {
		return nil, err
	}

	err = LoadEnvironmentVariables(ctx)
	if err != nil {
		return nil, err
	}
	err = LoadOverrideIfNeeded(ctx)
	if err != nil {
		return nil, err
	}

	// For logging before we get the service
	var provider *wool.Provider

	err = LoadService(ctx)
	if err != nil {
		return nil, err
	}

	if service == nil {
		fmt.Println("No service configuration found. Will use default log wrapper")
		provider = wool.New(ctx, configurations.CLI.AsResource()).WithConsole(GetLogLevel())
	} else {
		// Now update the provider
		provider = wool.New(ctx, service.Identity().AsResource()).WithConsole(GetLogLevel())
	}

	ctx = provider.Inject(ctx)

	return provider, nil
}

var root string
var service *configurations.Service

func LoadService(ctx context.Context) error {
	svc, err := configurations.LoadServiceFromDir(ctx, root)
	if err != nil {
		dir, errFind := configurations.FindUp[configurations.Service](ctx)
		if errFind != nil {
			return errFind
		}
		if dir != nil {
			svc, err = configurations.LoadServiceFromDir(ctx, *dir)
			if err != nil {
				return err
			}
		}
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

func Service() *configurations.Service {
	return service
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
	w := wool.Get(ctx).In("codefly.LoadOverrides")
	dir, err := shared.SolvePath(root)
	if err != nil {
		return w.Wrapf(err, "cannot solve dir")
	}
	config, err := configurations.LoadFromPath[Configuration](ctx, path.Join(dir, ".codefly.yaml"))
	if err != nil {
		return w.Wrapf(err, "cannot load override configuration")
	}
	for _, endpoint := range config.Endpoints {
		w.Debug("overloading endpoint", wool.Field("endpoint", endpoint), wool.Field("override", endpoint.Override))
		if strings.HasPrefix(endpoint.Name, "self") {
			// self is acceptable here for the endpoint as well
			if service == nil {
				return fmt.Errorf("self only allowed when a codefly service configuration is found")
			}
			endpoint.Name = strings.Replace(endpoint.Name, "self", service.Unique(), 1)
		}
		networkOverrides[endpoint.Name] = endpoint.Override
	}
	return nil
}

func GetEndpoint(ctx context.Context, unique string) (*configurations.EndpointInstance, error) {
	w := wool.Get(ctx).In("codefly.GetEndpoint")
	if strings.HasPrefix(unique, "self") {
		// self is acceptable here for the endpoint as well
		if service == nil {
			return nil, fmt.Errorf("self only allowed when a codefly service configuration is found")
		}
		unique = strings.Replace(unique, "self", service.Unique(), 1)
	}
	if override, ok := networkOverrides[unique]; ok {
		info, err := configurations.ParseEndpoint(unique)
		if err != nil {
			return nil, err
		}
		return &configurations.EndpointInstance{Endpoint: &configurations.Endpoint{
			Name:        info.Name,
			Service:     info.Service,
			Application: info.Application,
			API:         info.API,
		}, Address: override}, nil
	}
	instance, err := environmentManager.GetEndpoint(ctx, unique)
	if err != nil {
		w.Warn("not endpoint configuration found, returning standards")
		return configurations.DefaultEndpointInstance(unique)
	}
	return instance, nil
}

func GetProjectProvider(ctx context.Context, name string, key string) (string, error) {
	return environmentManager.GetProjectProvider(ctx, name, key)
}

func GetServiceProvider(ctx context.Context, unique string, name string, key string) (string, error) {
	return environmentManager.GetServiceProvider(ctx, unique, name, key)
}

func IsLocalEnvironment() bool {
	return os.Getenv(configurations.EnvironmentAsEnvironmentVariableKey) == configurations.Local().Name
}
