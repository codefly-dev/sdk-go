# Working in workcontext

This module's coverage gate is the **module total** across both its packages,
≥ 75%, computed with `awk` in CI (`.github/workflows/go.yml`, `coverage` job) —
not the root's `.testcoverage.yaml`, and the two are not interchangeable.
`grpctransport` sitting low is carried by the verifier: read the total, not a
package line.
