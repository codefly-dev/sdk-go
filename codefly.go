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

	mod, svc, err := resources.LoadModuleAndServiceFromCurrentPath(ctx)
	if err != nil {
		return nil, err
	}

	runningService = svc
	runningModule = mod
	if runningService == nil {
		fmt.Println("No service configuration found.")
		provider = wool.New(ctx, resources.CLI.AsResource()).WithConsole(GetLogLevel())
	} else {
		// Now update the provider
		id, err := runningService.Identity()
		if err != nil {
			return nil, err
		}
		provider = wool.New(ctx, id.AsResource()).WithConsole(GetLogLevel())
	}

	ctx = provider.Inject(ctx)

	return provider, nil
}

var root string
var runningService *resources.Service
var runningModule *resources.Module
var runningCtx context.Context

func Version() string {
	if runningService == nil {
		return "unknown"
	}
	return runningService.Version
}

func Service() *resources.Service {
	return runningService
}

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
