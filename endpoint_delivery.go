package codefly

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/solutionhost"
)

// ErrEndpointDeliveryUnavailable means no matching live delivery authorizes the
// route. It never permits fallback to a boot-time carrier or local port map.
var ErrEndpointDeliveryUnavailable = errors.New("codefly: applied endpoint delivery is unavailable")

// ResolveDeliveredNetworkInstance resolves a host route against the complete
// presence document the host has applied. The CLI supplies a stable directory
// and replaces its per-component projections on delivery; every call reads the
// current file, so introduction, relocation and withdrawal need no host restart.
//
// Core validates both the projection and its binding to the applied generation.
// Only the CLI-selected endpoint subset is available. Missing or malformed
// files, mismatched generations and absent endpoints fail closed, even when an
// environment carrier or local workspace could answer the same endpoint name.
func (q *Query) ResolveDeliveredNetworkInstance(applied *solutionhost.SolutionHostBinding) (*resources.NetworkInstance, error) {
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
	key := resources.EndpointDeliveryDirectoryKey
	directory, ok := injectedEnvironmentValue(key)
	if !ok || strings.TrimSpace(directory) == "" {
		directory = os.Getenv(key)
	}
	if strings.TrimSpace(directory) == "" {
		directory, _ = resources.FindValueInEnvironmentVariables(q.ctx, key, codeflyEnvironmentVariables())
	}
	if !filepath.IsAbs(directory) {
		return nil, fmt.Errorf("%w: no absolute delivery directory was supplied", ErrEndpointDeliveryUnavailable)
	}
	filename, err := solutionhost.EndpointDeliveryFilename(applied)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEndpointDeliveryUnavailable, err)
	}
	path := filepath.Join(directory, filename)
	stat, err := os.Stat(path)
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > solutionhost.EndpointDeliveryMaxBytes {
		return nil, fmt.Errorf("%w: projection is absent, oversized or not a regular file", ErrEndpointDeliveryUnavailable)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot open projection", ErrEndpointDeliveryUnavailable)
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, solutionhost.EndpointDeliveryMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read projection", ErrEndpointDeliveryUnavailable)
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
	if err := q.ctx.Err(); err != nil {
		return nil, err
	}
	return instance, nil
}
