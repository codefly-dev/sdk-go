package codefly

import (
	"context"
	"github.com/codefly-dev/core/configurations"
	"github.com/codefly-dev/core/wool"
)

type Query struct {
	application        string
	service            string
	endpointName       string
	endpointApi        string
	ctx                context.Context
	withDefaultNetwork bool
}

func For(ctx context.Context) *Query {
	q := &Query{ctx: ctx}
	if runningService != nil {
		q.application = runningService.Application
		q.service = runningService.Name
	}
	return q
}

func (q *Query) Service(s string) *Query {
	q.service = s
	return q
}

func (q *Query) Application(s string) *Query {
	q.application = s
	return q
}

func (q *Query) API(name string) *Query {
	q.endpointApi = name
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


func (q *Query) NetworkInstance() *configurations.NetworkInstance {
	w := wool.Get(q.ctx).In("NetworkInstance")
	q.Normalize()
	info := &configurations.EndpointInformation{
		Application: q.application,
		Service:     q.service,
		API:         q.endpointApi,
		Name:        q.endpointName,
	}
	instance, err := configurations.FindNetworkInstanceInEnvironmentVariables(q.ctx, info, envs)
	if err != nil {
		if q.withDefaultNetwork {
			w.Warn("Cannot find network instance, returning default", wool.Field("info", info), wool.Field("error", err))
			return configurations.DefaultNetworkInstance(q.endpointApi)
		}
		return nil
	}
	return instance
}

func (q *Query) Configuration(key string, name string) (string, error) {
	q.Normalize()
	unique := configurations.ServiceUnique(q.application, q.service)
	envKey := configurations.ServiceConfigurationKeyFromUnique(unique, key, name)
	return configurations.FindValueInEnvironmentVariables(q.ctx, envKey, envs)
}

func (q *Query) Secret(key string, name string) (string, error) {
	q.Normalize()
	unique := configurations.ServiceUnique(q.application, q.service)
	envKey := configurations.ServiceSecretConfigurationKeyFromUnique(unique, key, name)
	return configurations.FindValueInEnvironmentVariables(q.ctx, envKey, envs)
}
