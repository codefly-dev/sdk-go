package codefly

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/codefly-dev/core/resources"
)

// Module is the module this process belongs to: the identity Init pinned or,
// before Init, the one the runtime injected. Empty when neither names one.
func Module() string {
	if pinned := strings.TrimSpace(pinnedConsumerIdentity()); pinned != "" {
		return pinned
	}
	return strings.TrimSpace(os.Getenv(resources.ModulePrefix))
}

// AdvertisedNetworkInstance is the address the composition ADVERTISES for one
// of this process's own endpoints: what a peer dials to reach it, as opposed to
// what it listens on.
//
// The two differ exactly where it matters. A rendered cell localizes a
// service's own endpoint carrier to the address it binds ("localhost:8080"), so
// a process that told another component its listen address told it to dial its
// own loopback. The advertised address travels in its own carrier, and this
// reads it; ErrEndpointCarrierAbsent reports that none was injected, which a
// caller decides about (a local run may answer with its listen port, a deployed
// one may not). A carrier that is present and is not an address is an error,
// never absence.
//
// The query names the endpoint as ResolveNetworkInstance's does, and the
// module and service are this process's own.
func (q *Query) AdvertisedNetworkInstance() (*resources.NetworkInstance, error) {
	q.Normalize()
	info := q.canonicalInformation()
	if strings.TrimSpace(info.Module) == "" || strings.TrimSpace(info.Service) == "" {
		return nil, errors.New("module and service are required to read an advertised endpoint")
	}
	if strings.TrimSpace(info.Name) == "" || info.UnknownAPI() {
		return nil, fmt.Errorf("%w: an advertised endpoint is named by its endpoint and its API; name both", resources.ErrNoSuchEndpoint)
	}
	key := resources.SelfEndpointAsEnvironmentVariableKey(info)
	instance, err := resources.FindSelfNetworkInstanceInEnvironmentVariables(q.ctx, info, codeflyEnvironmentVariables())
	switch {
	case err == nil:
		return instance, nil
	case errors.Is(err, resources.ErrEndpointCarrierAbsent):
		return nil, fmt.Errorf("%w: no advertised address for %s (carrier %s)", ErrEndpointCarrierAbsent, endpointReference(info), key)
	default:
		return nil, fmt.Errorf("the advertised address carrier %s for %s cannot be read: %w", key, endpointReference(info), err)
	}
}
