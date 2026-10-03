module github.com/codefly-dev/sdk-go/workcontext

go 1.27.0

require (
	github.com/codefly-dev/core v0.7.2-0.20261003161926-4051e4383635
	github.com/stretchr/testify v1.12.1
	golang.org/x/tools v0.51.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260825204119-511051f7f437.2 // indirect
	buf.build/go/protovalidate v1.4.0 // indirect
	cel.dev/cel-go v0.32.0 // indirect
	cel.dev/expr v0.25.3 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/exp v0.0.0-20260820142414-ca536658362e // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260825221802-da73d73af1c5 // indirect
)

// RETRACTED: every version of THIS module published before the second Work
// Context implementation was deleted from it.
//
// This module carries the files from root tag v0.1.66 onward — they live under
// workcontext/, which is this module, so the root module's zip excludes them
// and the root module's retract directive says nothing about them. A review
// found the root retraction aimed at the wrong module and confirmed it from the
// cache: github.com/codefly-dev/sdk-go/workcontext@v0.0.0-20260928181007-c1fc359f112f
// resolves today and its zip contains work_context.go.
//
// A RANGE OF PSEUDO-VERSIONS, because this module has never been tagged: every
// version of it that a consumer can resolve is a pseudo-version of a commit,
// and every commit before this change carries the implementation. The high
// bound is a timestamp later than any of them and earlier than any release that
// could carry this file, so it covers all of them and none of what comes after.
//
// Effective only once workcontext/vX.Y.Z is tagged carrying this go.mod, which
// is the owner's release step.
retract [v0.0.0, v0.0.0-20261004000000-zzzzzzzzzzzz]
