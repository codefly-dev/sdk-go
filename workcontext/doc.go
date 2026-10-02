// Package workcontext signs and verifies Codefly Work Contexts — bounded,
// two-segment Ed25519 capabilities carried between execution boundaries — and
// holds the client a module process uses to obtain the one credential it runs
// on.
//
// A credential is minted once per execution and sealed to the execution that
// holds it: the principal and its epoch, the installation and its revision,
// and the build incarnation. Every sealed field is required, so a token
// carrying only delegation claims does not verify and cannot be attached to a
// request. Nothing here runs on a timer that is not the credential's own
// expiry: there is no heartbeat, no registration call, and nothing the process
// reports about itself, because the host establishes principal, installation
// and build from the projected service-account token and its own records.
//
// Verification is one path. VerifyWorkContext returns a VerifiedWorkContext,
// which is the only thing that produces verified claims, and an operation
// context resolves its sealed binding identity exactly rather than searching
// for a binding whose scopes would admit the call.
//
// It is a standalone module so a service whose only need is to verify Work
// Contexts against a JWKS can depend on the verifier without inheriting the
// full transitive dependency tail of github.com/codefly-dev/sdk-go. The gRPC
// transport for Work Contexts lives in the workcontext/grpctransport
// subpackage so that consumers that only verify never compile grpc.
//
// See README.md in this directory for the model, the four refusals a caller
// must tell apart, and what a consumer has to stop doing.
package workcontext
