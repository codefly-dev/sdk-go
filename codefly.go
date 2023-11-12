package codefly

import (
	"fmt"
	"github.com/codefly-dev/core/configurations"
	"github.com/codefly-dev/core/shared"
	"os"
	"path"
	"runtime/debug"
	"strings"
)

var logger = shared.NewLogger("codefly")
var networks map[string][]string

func CatchPanic() {
	if r := recover(); r != nil {
		logger.Message("Caught panic: %s", r)
		// Show the stack
		logger.Message("stacktrace:%s\n", string(debug.Stack()))
		os.Exit(1)
	}
}

func init() {
	// Probably make it a struct with some validation
	networks = make(map[string][]string)

	if os.Getenv("CODEFLY_SDK__LOGLEVEL") == "debug" {
		logger.SetLevel(shared.DebugLevel)
	} else if os.Getenv("CODEFLY_SDK__LOGLEVEL") == "trace" {
		logger.SetLevel(shared.TraceLevel)
	}

	// Default current root
	root, _ = os.Getwd()

	LoadEnvironmentVariables()

	err := LoadService()
	if err != nil {
		logger.Warn(shared.NewUserWarning("couldn't load codefly service configuration: %v", err))
	}

	if os.Getenv("CODEFLY_SDK__WITHOVERRIDE") == "true" {
		LoadOverrides()
	}

}

var root string
var configuration *configurations.Service

func WithRoot(dir string) {
	root = dir
	err := LoadService()
	if err != nil {
		logger.Warn(shared.NewUserWarning("couldn't load codefly service configuration: %v", err))
	}
	LoadOverrides()
}

func WithDebug() {
	logger.SetLevel(shared.DebugLevel)
}

func WithTrace() {
	logger.SetLevel(shared.TraceLevel)
}

func LoadService() error {
	svc, err := configurations.LoadFromDir[configurations.Service](root)
	if err != nil {
		return err
	}
	configuration = svc
	return nil
}

func Version() string {
	if configuration == nil {
		return "unknown"
	}
	return configuration.Version
}

func LoadEnvironmentVariables() {
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "CODEFLY") {
			continue
		}
		logger.Debugf("checking environment variable: %s", env)
		if ok := strings.HasPrefix(env, configurations.EndpointPrefix); ok {
			instance, err := configurations.ParseEndpointEnvironmentVariable(env)
			if err != nil {
				logger.Warn(shared.NewUserWarning("cannot parse endpoint environment variable: %s", err))
				continue
			}
			logger.Debugf("env translation: %s -> %s", env, instance)
			networks[instance.Unique] = instance.Addresses
		}
	}
}

type EndpointOverride struct {
	Name     string
	Override string
}

type Configuration struct {
	Endpoints []EndpointOverride
}

func LoadOverrides() {
	config, err := configurations.LoadFromPath[Configuration](path.Join(root, ".codefly.yaml"))
	if err != nil {
		logger.Tracef("not using any overrides config")
		return
	}
	for _, endpoint := range config.Endpoints {
		logger.Tracef("overloading endpoint: %s -> %s", endpoint.Name, endpoint.Override)
		networks[endpoint.Name] = []string{endpoint.Override}
	}
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

func Endpoint(name string) INetworkEndpoint {
	if endpoint, ok := networks[name]; ok {
		return &NetworkEndpoint{Values: endpoint}
	}
	if r, ok := strings.CutPrefix(name, "self"); ok {
		if configuration == nil {
			shared.Exit("cannot use self without a codefly service configuration")
		}
		name = fmt.Sprintf("%s/%s%s", configuration.Application, configuration.Name, r)
		if endpoint, ok := networks[name]; ok {
			return &NetworkEndpoint{Values: endpoint}
		}
	}
	logger.Warn(shared.NewUserWarning("did not find any codefly network endpoint for %s", name))
	return &NetworkEndpointNotFound{}
}
