// Package workcontext signs and verifies Codefly Work Contexts: bounded,
// two-segment Ed25519 capabilities carried between execution boundaries.
//
// It is a standalone module so a service whose only need is to verify Work
// Contexts against a JWKS can depend on the verifier without inheriting the
// full transitive dependency tail of github.com/codefly-dev/sdk-go. The gRPC
// transport for Work Contexts lives in the workcontext/grpctransport
// subpackage so that consumers that only verify never compile grpc.
package workcontext
