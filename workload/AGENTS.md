# workload/ and ingress/

`workload` is a workload's X.509-SVID identity held to one posture in both
directions — the listener a peer calls it on, and the client it dials the
platform with. It was **moved** from codefly-dev/solution-runtime-go
(`identity.go`, and the outbound half of `solution.go`); every rule in it was
established there against a demonstrated bypass, and the comments keep those
arguments. Read the comment before changing the rule it sits on.

- **Nothing here is trusted from a probe.** What a handshake selects is what is
  compared to the frozen principal (`holdServedCertificate`,
  `holdPresentedCertificate`); a peer's identity is read from a private parse of
  the DER (`immutableChain`), never from objects crypto/tls shares.
- **Admission sets are read per handshake and fail closed** (`IdentitySet`):
  an unreadable or empty set refuses; a file not ending in a newline is a
  fragment and refuses. The anchor is read per handshake too. Established
  connections are rechecked every second in both directions.
- **A source cannot replace the posture, only satisfy it**
  (`usableServerIdentity`, `unsubvertedPosture`, `holdPerConnectionPosture`).
  Resumption is off. HTTP/2 is not negotiated (the admitted-identity pin runs in
  a hook net/http skips for h2).
- **The import gate names these files and symbols.** `crypto/tls`,
  `crypto/x509` and `encoding/json` are held to named files and symbols in
  `scripts/allowed-imports.txt` and `workcontext/one_implementation_test.go`
  (`narrowedImports`, `endpointJSONBodies`). A new symbol is a gate edit argued
  in the PR, never a nolint.

`ingress` is one consumer: a module's TLS-only listener for the host's gateway
(endpoint `ingress`, api `http`) and the report of its advertised https origin
to the host's `/modules/_upstream`, on the credential mint's origin, presenting
the SVID and the projected token to an identity both the gateway and the mint
sets admit. Tests issue their own anchor (`cell_test.go`); mutation-check a new
rule by disabling it and watching its test fail.
