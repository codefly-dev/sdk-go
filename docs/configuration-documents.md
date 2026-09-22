# Structured configuration

The runtime transports JSON-compatible configuration documents without flattening
their keys. Select a service with the existing query API:

```go
query := codefly.For(ctx).Module("app").Service("api")
document, err := query.ConfigurationDocument("settings")
```

`SecretDocument` selects a separate secret namespace. Workspace documents use
`WorkspaceConfigurationDocument` and `WorkspaceSecretDocument`. All return an
independent `json.RawMessage`; callers must not log secret documents.

For typed decoding, use `DecodeConfigurationDocument(name, &destination)`,
`DecodeSecretDocument`, `DecodeWorkspaceConfigurationDocument`, or
`DecodeWorkspaceSecretDocument`. Untyped numeric destinations use `json.Number`
instead of rounding large integers through `float64`.

Lookups use the injected configuration snapshot, then the process environment,
then the SDK environment snapshot. Empty carriers are absent. Missing documents,
malformed carriers, unsupported versions and mismatched service or environment
scopes are errors. Decoder errors never include document content. These accessors
read runtime carriers; they do not independently resolve local secret providers.

Core owns the `codefly/configuration-document/v1` encoding and the 64 KiB bound
on each source document and encoded carrier. The existing directory loader uses
`.yaml` and `.secret.yaml`; direct protobuf data may specify JSON or YAML. The
runtime converts JSON-compatible YAML once. Public and secret documents remain
separate, and ordinary flat configuration strings keep their existing API.
