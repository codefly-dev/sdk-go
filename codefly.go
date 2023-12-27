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

var networks map[string][]string

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

	// Probably make it a struct with some validation
	networks = make(map[string][]string)

	err = LoadNetworkEndpointFromEnvironmentVariables(ctx)
	if err != nil {
		return nil, err
	}

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

func LoadNetworkEndpointFromEnvironmentVariables(ctx context.Context) error {
	w := wool.Get(ctx).In("codefly.LoadNetworkEndpointFromEnvironmentVariables")
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "CODEFLY") {
			continue
		}
		w.Trace("checking environment variable", wool.Field("env", env))
		if ok := strings.HasPrefix(env, configurations.EndpointPrefix); ok {
			instance, err := configurations.ParseEndpointEnvironmentVariable(env)
			if err != nil {
				return err
			}
			w.Trace("env translation", wool.Field("from", env), wool.Field("to", instance.Addresses))
			networks[instance.Unique] = instance.Addresses
		}
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
		networks[endpoint.Name] = []string{endpoint.Override}
	}
	return nil
}

type INetworkEndpoint interface {
	IsPresent() bool
	WithDefault(backup string) INetworkEndpoint

	Host() string
	PortAddress() string
}

type NetworkEndpointNotFound struct {
}

func (e *NetworkEndpointNotFound) Host() string {
	return "localhost"
}

func (e *NetworkEndpointNotFound) PortAddress() string {
	return ":8080"
}

func (e *NetworkEndpointNotFound) IsPresent() bool {
	return false
}

func (e *NetworkEndpointNotFound) WithDefault(backup string) INetworkEndpoint {
	return e
}

type NetworkEndpoint struct {
	Values []string
}

func (e *NetworkEndpoint) IsPresent() bool {
	return true
}

func (e *NetworkEndpoint) WithDefault(backup string) INetworkEndpoint {
	if e.Values == nil {
		e.Values = []string{backup}
	}
	return e
}

func (e *NetworkEndpoint) Host() string {
	// Not great
	return e.Values[0]
}

func (e *NetworkEndpoint) PortAddress() string {
	return ":" + strings.Split(e.Values[0], ":")[1]
}

func Endpoint(ctx context.Context, name string) INetworkEndpoint {
	w := wool.Get(ctx).In("codefly.Endpoint", wool.NameField(name))
	endpoint, err := GetEndpoint(ctx, name)
	if err == nil {
		return endpoint
	}
	w.Error("cannot find endpoint", wool.ErrField(err))
	return &NetworkEndpointNotFound{}
}

func GetEndpoint(ctx context.Context, name string) (*NetworkEndpoint, error) {
	w := wool.Get(ctx).In("codefly.Endpoint", wool.NameField(name))
	if endpoint, ok := networks[name]; ok {
		return &NetworkEndpoint{Values: endpoint}, nil
	}
	if r, ok := strings.CutPrefix(name, "self"); ok {
		if service == nil {
			return nil, w.NewError("cannot use self endpoint without a service")
		}
		name = fmt.Sprintf("%s/%s%s", service.Application, service.Name, r)
		if endpoint, ok := networks[name]; ok {
			return &NetworkEndpoint{Values: endpoint}, nil
		}
		return nil, w.NewError("did not find any codefly network endpoint self: %s", name)
	}
	return nil, w.NewError("did not find any codefly network endpoint")
}
