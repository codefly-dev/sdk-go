package codefly

import (
	"fmt"
	"github.com/codefly-dev/core/configurations"
	"github.com/codefly-dev/core/shared"
	"os"
	"strings"
)

var logger = shared.NewLogger("codefly")
var networks map[string]string

func init() {

	networks = make(map[string]string)
	LoadEnvironmentVariables()
	LoadService()
}

var root string
var configuration *configurations.Service

func WithRoot(dir string) {
	root = dir
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
		if p, ok := strings.CutPrefix(env, "CODEFLY-NETWORK_"); ok {
			tokens := strings.Split(p, "=")
			key := strings.ToLower(tokens[0])
			// Namespace break
			key = strings.Replace(key, "_", ".", 1)
			key = strings.Replace(key, "_", "::", 1)
			value := tokens[1]
			networks[key] = value
		}
	}
}

type NetworkEndpoint struct {
	Value string
}

func (e *NetworkEndpoint) WithDefault(backup string) *NetworkEndpoint {
	if e.Value == "" {
		e.Value = backup
	}
	return e
}

func (e *NetworkEndpoint) Host() string {
	return e.Value
}

func (e *NetworkEndpoint) PortAddress() string {
	return ":" + strings.Split(e.Value, ":")[1]
}

func Endpoint(name string) *NetworkEndpoint {
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
		return &NetworkEndpoint{Value: endpoint}
	}
	shared.Exit("cannot find endpoint <%s>", name)
	return nil
}

func Value(name string) bool {
	return true
}

func Endpoints() []string {
	var endpoints []string
	for k, v := range networks {
		endpoints = append(endpoints, fmt.Sprintf("%s=%s", k, v))
	}
	return endpoints
}
