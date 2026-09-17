## Summary

<!-- Why this change exists, not a recap of the diff. -->

## Fix or hack

<!--
A fix lives at the place that owns the behaviour. Anything else is a hack —
being small, local, or blocked on another repo does not change that. If it is a
hack, link the issue against the owner. See AGENTS.md.
-->

## Test plan

- [ ] `go test ./...` and `(cd workcontext && go test ./...)`
- [ ] `go test -race ./...` and `(cd workcontext && go test -race ./...)`
- [ ] `golangci-lint run` in each module
- [ ] `go mod tidy` clean in each module

## Not verified

<!-- What you could not exercise. Unverified is not the same as working. -->
