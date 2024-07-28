package codefly

import (
	"context"
	"fmt"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/wool"
	"os"
	"runtime/debug"
	"strings"
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
	if os.Getenv("CODEFLY__SDK__LOGLEVEL") == "debug" {
		return wool.DEBUG
	} else if os.Getenv("CODEFLY__SDK__LOGLEVEL") == "trace" {
		return wool.TRACE
	}
	return wool.INFO
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

	err = LoadEnvironmentVariables()

	if err != nil {
		return nil, err
	}
	// For logging before we get the runningService
	var provider *wool.Provider

	service = os.Getenv("CODEFLY__SERVICE")
	module = os.Getenv("CODEFLY__MODULE")

	// Now update the provider
	id := resources.ServiceIdentity{Name: service, Module: module}
	provider = wool.New(ctx, id.AsResource()).WithConsole(GetLogLevel())

	ctx = provider.Inject(ctx)

	return provider, nil
}

var root string
var runningCtx context.Context

var envs []string
var uniqueEnvs = make(map[string]bool)

func LoadEnvironmentVariables() error {
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "CODEFLY") {
			continue
		}
		if _, ok := uniqueEnvs[env]; ok {
			continue
		}
		uniqueEnvs[env] = true
		envs = append(envs, env)
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

func WithFixture(fixture string) bool {
	return os.Getenv("CODEFLY__FIXTURE") == fixture
}
