![workflow](https://github.com/codefly-dev/sdk-go/actions/workflows/go.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/codefly-dev/sdk-go)](https://goreportcard.com/report/github.com/codefly-dev/sdk-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/codefly-dev/sdk-go.svg)](https://pkg.go.dev/github.com/codefly-dev/sdk-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


![](docs/media/dragonfly.png)

# codefly + go = sdk-go

## Authenticated Postgres capabilities

`github.com/codefly-dev/sdk-go/postgres` binds Codefly's separate Postgres
reader/writer credentials to a verified request principal. The factory keeps
raw pools private, installs tenant and user identity with transaction-local
settings, starts reads as database-enforced read-only transactions, and asks
the application authorizer before issuing a writer. It deliberately exposes no
admin or RLS-bypass path.

Application repositories accept `postgres.ReadTx` or `postgres.WriteTx`; they
do not accept tenant IDs. RLS policies derive tenant scope from
`codefly.current_tenant_id` (or names configured with `WithScopeSettings`).

