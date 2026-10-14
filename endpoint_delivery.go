package codefly

import (
	"errors"
	"fmt"

	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/solutionhost"
)

// ErrEndpointDeliveryUnavailable means no matching live delivery authorizes the
// route. It never permits fallback to a boot-time carrier or local port map.
var ErrEndpointDeliveryUnavailable = errors.New("codefly: applied endpoint delivery is unavailable")

// ResolveDeliveredNetworkInstance resolves a host route against the complete
// presence document the host has applied and the endpoint delivery value the
// host carries beside that applied generation in its durable delivery state.
// The caller passes both. Nothing here reads a file, a directory or the
// environment, so there is no mount and no restart: a route update is whatever
// the host hands over on the next call.
//
// Core validates the value against the whole canonical applied document and
// the SDK decodes the one endpoint the query names. A nil or empty value, a
// value over solutionhost.EndpointDeliveryMaxBytes, a mismatched generation, a
// malformed value and an endpoint the producer did not deliver all fail
// closed, even when an environment carrier or a local workspace could answer
// the same endpoint name. The value is read once and not retained.
func (q *Query) ResolveDeliveredNetworkInstance(applied *solutionhost.SolutionHostBinding, raw []byte) (*resources.NetworkInstance, error) {
	if err := checkConsumerIdentity(q.consumerModule); err != nil {
		return nil, err
	}
	if err := q.ctx.Err(); err != nil {
		return nil, err
	}
	q.Normalize()
	info := q.canonicalInformation()
	if info.Module == "" || info.Service == "" || info.Name == "" || info.UnknownAPI() {
		return nil, fmt.Errorf("%w: module, service, endpoint and API are required", ErrEndpointDeliveryUnavailable)
	}
	if applied == nil {
		return nil, fmt.Errorf("%w: no applied presence document was supplied", ErrEndpointDeliveryUnavailable)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: no endpoint delivery value was supplied", ErrEndpointDeliveryUnavailable)
	}
	if len(raw) > solutionhost.EndpointDeliveryMaxBytes {
		return nil, fmt.Errorf("%w: the endpoint delivery value exceeds %d bytes", ErrEndpointDeliveryUnavailable, solutionhost.EndpointDeliveryMaxBytes)
	}
	projection, err := solutionhost.ParseEndpointDelivery(raw, applied)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEndpointDeliveryUnavailable, err)
	}
	address, present := projection.Carriers[resources.EndpointAsEnvironmentVariableKey(info)]
	if !present {
		return nil, fmt.Errorf("%w: endpoint was not delivered", ErrEndpointDeliveryUnavailable)
	}
	instance, err := resources.ParseAddress(address)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed endpoint address", ErrEndpointDeliveryUnavailable)
	}
	return instance, nil
}
