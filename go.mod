module github.com/codefly-dev/sdk-go

go 1.27.0

require (
	connectrpc.com/connect v1.21.0
	github.com/codefly-dev/core v0.7.1
	github.com/jackc/pgx/v5 v5.11.0
	github.com/stretchr/testify v1.12.1
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260825204119-511051f7f437.2 // indirect
	buf.build/go/protovalidate v1.4.0 // indirect
	cel.dev/cel-go v0.32.0 // indirect
	cel.dev/expr v0.25.3 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Masterminds/semver/v3 v3.5.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/go-openapi/analysis v1.0.0 // indirect
	github.com/go-openapi/errors v0.22.8 // indirect
	github.com/go-openapi/jsonpointer v1.0.1 // indirect
	github.com/go-openapi/jsonreference v1.0.2 // indirect
	github.com/go-openapi/loads v0.25.3 // indirect
	github.com/go-openapi/spec v1.0.1 // indirect
	github.com/go-openapi/strfmt v0.27.2 // indirect
	github.com/go-openapi/swag/conv v0.29.1 // indirect
	github.com/go-openapi/swag/jsonutils v0.29.1 // indirect
	github.com/go-openapi/swag/loading v0.29.1 // indirect
	github.com/go-openapi/swag/mangling v0.29.1 // indirect
	github.com/go-openapi/swag/pools v0.29.1 // indirect
	github.com/go-openapi/swag/stringutils v0.29.1 // indirect
	github.com/go-openapi/swag/typeutils v0.29.1 // indirect
	github.com/go-openapi/swag/yamlutils v0.29.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/gofrs/flock v0.13.1 // indirect
	github.com/google/go-github/v89 v89.0.0 // indirect
	github.com/google/go-querystring v1.2.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/oklog/ulid/v2 v2.1.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/yoheimuta/go-protoparser/v4 v4.14.2 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/exp v0.0.0-20260820142414-ca536658362e // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/term v0.46.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260825221802-da73d73af1c5 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// RETRACTED: the ROOT module's versions that publish a second Work Context
// implementation.
//
// A branch that carries it can be deleted. A TAG CANNOT: it is an immutable
// published artifact, `go get sdk-go@v0.1.65` resolves it right now, and the
// module proxy has it cached forever. So the rule for a tag is not "clean", it
// is RETRACTED — the one mechanism Go provides for "this published version
// should not be used", which `go get` and `go list -m -u` both report.
//
// FIFTEEN, not nineteen, and the difference is the finding that corrected this.
// A previous revision retracted v0.1.51 through v0.1.68 and v0.2.0 on the
// strength of sweeping each tag's whole TREE. But from v0.1.66 the files moved
// under workcontext/, which has its own go.mod — so the root module's zip for
// those versions does not contain them, the root versions are CLEAN, and the
// module that carries them is github.com/codefly-dev/sdk-go/workcontext, whose
// go.mod had no retract at all. Retracting a clean version is not a safe error
// in the same direction: it tells consumers to move off something that was
// never the problem, while the thing that was stayed resolvable.
//
// workcontext/go.mod retracts the leaf side.
//
// TWO THINGS THIS DOES NOT DO, both belonging to whoever tags releases: a
// retraction takes effect only once a NEW version is tagged carrying this
// go.mod, and nothing here deletes anything from the proxy, because nothing
// can.
retract [v0.1.51, v0.1.65] // a second Work Context implementation at the root
