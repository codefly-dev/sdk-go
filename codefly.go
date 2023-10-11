package codefly

import (
	"fmt"
	"os"
	"strings"
)

var networks map[string]string

func init() {
	networks = make(map[string]string)
	Load()
}

func Load() {

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
	fmt.Printf("VALUE <%s>\n", e.Value)
	return ":" + strings.Split(e.Value, ":")[1]
}

func Endpoint(name string) *NetworkEndpoint {
	return &NetworkEndpoint{Value: networks[name]}
}

func Value(name string) bool {
	return true
}

func Endpoints() []string {
	var endpoints []string
	for k, v := range networks {
		endpoints = append(endpoints, k+"="+v)
	}
	return endpoints
}
