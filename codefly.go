package codefly

import (
	"fmt"
	"github.com/codefly-dev/core/configurations"
	"github.com/codefly-dev/core/shared"
	"os"
	"path"
	"strings"
)

var logger = shared.NewLogger("codefly")
var networks map[string][]string

func init() {
	WithTrace()

	networks = make(map[string][]string)
	LoadEnvironmentVariables()
	LoadOverrides()
	LoadService()
}

var root string
var configuration *configurations.Service

func WithRoot(dir string) {
	root = dir
}

func WithDebug() {
	logger.SetDebug()
}

func WithTrace() {
	logger.SetTrace()
}

func LoadService() {
	svc, err := configurations.LoadFromDir[configurations.Service](root)
	if err != nil {
		logger.Warn(shared.NewUserWarning("did not find any codefly service configuration"))
	}
	configuration = svc
}

func LoadEnvironmentVariables() {
	for _, env := range os.Environ() {
		if p, ok := strings.CutPrefix(env, configurations.NetworkPrefix); ok {
			reference, addresses := configurations.ParseEnvironmentVariable(p)
			networks[reference] = addresses
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
		logger.Tracef("no config found")
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
	if r, ok := strings.CutPrefix(name, "self"); ok {
		if configuration == nil {
			shared.Exit("cannot use self without a codefly service configuration")
		}
		if nonDefault, ok := strings.CutPrefix(r, "::"); ok {
			name = fmt.Sprintf("%s::%s", configuration.Endpoint(), nonDefault)
		} else {
			name = configuration.Endpoint()
		}
	}
	if endpoint, ok := networks[name]; ok {
		return &NetworkEndpoint{Values: endpoint}
	}
	logger.Warn(shared.NewUserWarning("did not find any codefly network endpoint for %s", name))
	return &NetworkEndpointNotFound{}
}
