// Package fixture builds the descriptors the receipts tests run against.
//
// The interceptor reads the operation option off descriptors, so the fixtures
// are descriptors, built here rather than generated: a checked-in .pb.go would
// be an artifact nothing in this repo regenerates, and this module has no proto
// toolchain by design — the schema is codefly-dev/core's.
package fixture

import (
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/durationpb"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	runnablev0 "github.com/codefly-dev/core/generated/go/codefly/runnable/v0"
)

const (
	// Package is the proto package the fixture service lives in.
	Package = "codefly.receiptsfixture.v0"
	// OperationMethod carries the operation option.
	OperationMethod = "/" + Package + ".Fixture/Commit"
	// PlainMethod does not, so a call on it must pass through untouched.
	PlainMethod = "/" + Package + ".Fixture/Read"
	// RequestMessage and AnswerMessage are the fixture service's messages.
	RequestMessage = Package + ".Request"
	AnswerMessage  = Package + ".Answer"
)

// Registry is the descriptor set and message types one fixture service is
// registered in, private to a test so the process-wide registries stay clean.
type Registry struct {
	Files *protoregistry.Files
	Types *protoregistry.Types
}

// Operation is the execution policy the fixture's marked method declares. It is
// a conforming one: core refuses a policy the runtime would refuse to install,
// and the interceptor refuses to start over a method carrying such a policy.
func Operation() *runnablev0.Operation {
	return &runnablev0.Operation{
		AttemptTimeout: durationpb.New(10 * time.Second),
		TotalTimeout:   durationpb.New(30 * time.Second),
		MaxAttempts:    3,
		Backoff:        durationpb.New(time.Second),
		RetryableCodes: []string{"UNAVAILABLE"},
		Audience:       "codefly.receiptsfixture",
		InvokeScopes: []*basev0.WorkScopeV1{{
			ResourceKind: "fixture",
			Actions:      []string{"read", "write"},
		}},
		LookupScopes: []*basev0.WorkScopeV1{{
			ResourceKind: "fixture",
			Actions:      []string{"read"},
		}},
	}
}

// New compiles the fixture service, marking its Commit method with the declared
// operation. A nil declaration leaves both methods unmarked.
func New(declared *runnablev0.Operation) (Registry, error) {
	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("codefly/receiptsfixture/v0/fixture.proto"),
		Package: proto.String(Package),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			payload("Request"),
			payload("Answer"),
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("Fixture"),
			Method: []*descriptorpb.MethodDescriptorProto{
				method("Commit", declared),
				method("Read", nil),
			},
		}},
	}
	compiled, err := protodesc.NewFile(file, protoregistry.GlobalFiles)
	if err != nil {
		return Registry{}, err
	}
	files := &protoregistry.Files{}
	if err = files.RegisterFile(compiled); err != nil {
		return Registry{}, err
	}
	types := &protoregistry.Types{}
	messages := compiled.Messages()
	for index := range messages.Len() {
		if err = types.RegisterMessage(dynamicpb.NewMessageType(messages.Get(index))); err != nil {
			return Registry{}, err
		}
	}
	return Registry{Files: files, Types: types}, nil
}

// Message builds one fixture message with its single field set, so a test can
// vary a request without a generated type.
func (r Registry) Message(name protoreflect.FullName, value string) (proto.Message, error) {
	found, err := r.Types.FindMessageByName(name)
	if err != nil {
		return nil, err
	}
	built := found.New()
	built.Set(found.Descriptor().Fields().ByName("value"), protoreflect.ValueOfString(value))
	return built.Interface(), nil
}

func payload(name string) *descriptorpb.DescriptorProto {
	return &descriptorpb.DescriptorProto{
		Name: proto.String(name),
		Field: []*descriptorpb.FieldDescriptorProto{{
			Name:   proto.String("value"),
			Number: proto.Int32(1),
			Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
		}},
	}
}

func method(name string, declared *runnablev0.Operation) *descriptorpb.MethodDescriptorProto {
	built := &descriptorpb.MethodDescriptorProto{
		Name:       proto.String(name),
		InputType:  proto.String("." + RequestMessage),
		OutputType: proto.String("." + AnswerMessage),
	}
	if declared != nil {
		built.Options = &descriptorpb.MethodOptions{}
		proto.SetExtension(built.Options, runnablev0.E_Operation, declared)
	}
	return built
}
