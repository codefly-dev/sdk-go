// Package workcontext signs and verifies Codefly Work Contexts: bounded,
// two-segment Ed25519 capabilities carried between execution boundaries.
//
// It lives in its own module so a service whose only need is to verify Work
// Contexts against a JWKS can depend on the verifier without inheriting the
// full transitive dependency tail of github.com/codefly-dev/sdk-go.
package workcontext
