// Package workload is a workload's X.509-SVID identity, held to one posture in
// both directions: the listener a peer calls it on, and the client it presents
// itself to the platform with.
//
// It was moved here from the solution runtime (codefly-dev/solution-runtime-go,
// identity.go and the outbound half of solution.go), where every rule in it was
// established against a demonstrated bypass. A module service that serves the
// host's gateway needs the same listener and the same client, and a second copy
// is a second set of rules to keep in step; so the rules live here, generalised
// over the three things the runtime used to read off its own server — the
// principal this workload is held to, who may call it, and who may answer at
// each destination it dials.
package workload

import (
	"context"
	"strings"

	codefly "github.com/codefly-dev/sdk-go"
)

// Group is the workspace configuration group the platform provisions a
// workload's identity through. A service declares it among its
// workspace-configuration-dependencies, and the composition projects the files
// below into it.
const Group = "workload-identity"

// The keys of Group: each names a FILE the platform projected, never the
// material itself.
const (
	// CertFileKey and KeyFileKey are this workload's X.509-SVID and its key.
	CertFileKey = "CERT_FILE"
	KeyFileKey  = "KEY_FILE"
	// TrustBundleFileKey is the anchor peers are verified against, in both
	// directions.
	TrustBundleFileKey = "TRUST_BUNDLE_FILE"
	// AllowedCallersFileKey lists the SPIFFE IDs this workload's listener
	// serves. Every workload in the trust domain holds a certificate from the
	// anchor, so the anchor answers "did this cell issue it" and this file
	// answers "may it call me".
	AllowedCallersFileKey = "ALLOWED_CALLERS_FILE"
	// MintPeersFileKey and GatewayPeersFileKey list the identities allowed to
	// answer at each platform destination this workload dials.
	MintPeersFileKey    = "MINT_PEERS_FILE"
	GatewayPeersFileKey = "GATEWAY_PEERS_FILE"
	// TokenFileKey is the projected ServiceAccount token the host reviews.
	TokenFileKey = "TOKEN_FILE"
)

// The runtime values that override each file, addressed by name through
// codefly.RuntimeValue so the carrier encoding stays the SDK's. A local
// toolchain that writes the files somewhere a render would not sets these.
const (
	CertFileOverride           = "WORKLOAD_IDENTITY_CERT_FILE"
	KeyFileOverride            = "WORKLOAD_IDENTITY_KEY_FILE"
	TrustBundleFileOverride    = "WORKLOAD_IDENTITY_TRUST_BUNDLE_FILE"
	AllowedCallersFileOverride = "WORKLOAD_IDENTITY_ALLOWED_CALLERS_FILE"
	MintPeersFileOverride      = "WORKLOAD_IDENTITY_MINT_PEERS_FILE"
	GatewayPeersFileOverride   = "WORKLOAD_IDENTITY_GATEWAY_PEERS_FILE"
	TokenFileOverride          = "WORKLOAD_TOKEN_FILE"
)

// Files is where the platform projected this workload's identity. An empty
// field is one neither the override nor the group resolved; the consumer that
// needs it refuses by name, because there is no default path that is true on
// more than one platform.
type Files struct {
	Cert, Key, TrustBundle  string
	AllowedCallers          string
	MintPeers, GatewayPeers string
	Token                   string
}

// ProjectedFiles resolves Files: an explicit override first, then the
// workspace configuration group the platform populates.
func ProjectedFiles(ctx context.Context) Files {
	return Files{
		Cert:           projectedPath(ctx, CertFileOverride, CertFileKey),
		Key:            projectedPath(ctx, KeyFileOverride, KeyFileKey),
		TrustBundle:    projectedPath(ctx, TrustBundleFileOverride, TrustBundleFileKey),
		AllowedCallers: projectedPath(ctx, AllowedCallersFileOverride, AllowedCallersFileKey),
		MintPeers:      projectedPath(ctx, MintPeersFileOverride, MintPeersFileKey),
		GatewayPeers:   projectedPath(ctx, GatewayPeersFileOverride, GatewayPeersFileKey),
		Token:          projectedPath(ctx, TokenFileOverride, TokenFileKey),
	}
}

func projectedPath(ctx context.Context, override, key string) string {
	if value, ok := codefly.RuntimeValue(override); ok {
		return value
	}
	// The SDK's error carries no information here: it is the same "no value"
	// whether the group was never declared or never loaded, and the consumer
	// refuses the empty path by name either way.
	value, _ := codefly.For(ctx).WorkspaceConfiguration(Group, key)
	return strings.TrimSpace(value)
}
