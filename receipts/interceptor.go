package receipts

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/codefly-dev/core/runnable"
)

// Options configures an Interceptor.
type Options struct {
	// Store holds the receipts. Required.
	Store Store
	// Tenant reads the tenant of the caller's verified Work Context.
	//
	// Receipts never verifies a Work Context itself — the verifier is the
	// separate github.com/codefly-dev/sdk-go/workcontext module, which the root
	// SDK must not depend on — so the module's own authentication interceptor,
	// which has already verified the context by the time this one runs, says
	// where the tenant is. Required: a receipt without a tenant would let one
	// tenant read another's outcome.
	Tenant func(ctx context.Context) (string, error)
	// Files is where the operation option is read from. Nil means
	// protoregistry.GlobalFiles, which is what the module's own generated code
	// registers itself into.
	Files *protoregistry.Files
	// Types resolves the response message a replayed receipt is decoded into.
	// Nil means protoregistry.GlobalTypes.
	Types *protoregistry.Types
}

// Interceptor applies the replay and conflict rules to every method carrying
// codefly.runnable.v0.operation. A method without the option is untouched.
//
// It never writes a receipt. The write is the handler's, inside the transaction
// that commits the effect; see the package documentation.
type Interceptor struct {
	store      Store
	tenant     func(ctx context.Context) (string, error)
	operations map[string]protoreflect.MessageType
}

// New reads the marked methods off the descriptors registered in the process
// and returns the interceptor guarding them.
func New(options Options) (*Interceptor, error) {
	if options.Store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if options.Tenant == nil {
		return nil, fmt.Errorf("%w: a tenant resolver is required", ErrInvalid)
	}
	files := options.Files
	if files == nil {
		files = protoregistry.GlobalFiles
	}
	types := options.Types
	if types == nil {
		types = protoregistry.GlobalTypes
	}
	operations, err := markedOperations(files, types)
	if err != nil {
		return nil, err
	}
	return &Interceptor{store: options.Store, tenant: options.Tenant, operations: operations}, nil
}

// IsOperation reports whether a method carries the operation option, so a
// transport can leave an unmarked call entirely alone.
func (i *Interceptor) IsOperation(method string) bool {
	_, marked := i.operations[method]
	return marked
}

// Handle runs one incoming call under the replay and conflict rules.
//
// A method without the operation option is handed straight to the handler. A
// marked one must present an effect id, and is then either answered from the
// receipt it already committed or admitted — exactly once, even when two first
// attempts arrive together — with the effect placed in the handler's context.
func (i *Interceptor) Handle(
	ctx context.Context,
	method string,
	effectID string,
	request proto.Message,
	handler func(ctx context.Context) (proto.Message, error),
) (proto.Message, error) {
	response, marked := i.operations[method]
	if !marked {
		return handler(ctx)
	}
	if effectID == "" {
		return nil, fmt.Errorf("%w on %s", ErrEffectIDMissing, method)
	}
	if err := validateBounded("effect id", effectID, maxEffectIDBytes); err != nil {
		return nil, err
	}
	tenant, err := i.tenant(ctx)
	if err != nil {
		return nil, err
	}
	if err = validateBounded("tenant", tenant, maxTenantBytes); err != nil {
		return nil, err
	}
	digest, err := RequestDigest(request)
	if err != nil {
		return nil, err
	}

	release, err := i.store.Serialize(ctx, tenant, effectID, method)
	if err != nil {
		return nil, err
	}
	defer release()

	committed, found, err := i.store.Lookup(ctx, tenant, effectID, method)
	if err != nil {
		return nil, err
	}
	if found {
		if !bytes.Equal(committed.RequestDigest, digest) {
			return nil, fmt.Errorf("%w on %s", ErrEffectIDReused, method)
		}
		replayed := response.New().Interface()
		if err = proto.Unmarshal(committed.Response, replayed); err != nil {
			return nil, fmt.Errorf("%w: decode the recorded response: %v", ErrInvalid, err)
		}
		return replayed, nil
	}
	return handler(WithEffect(ctx, Effect{
		ID:            effectID,
		Tenant:        tenant,
		Method:        method,
		RequestDigest: digest,
	}))
}

// markedOperations walks every registered service for methods carrying the
// operation option.
//
// A marked method whose policy core refuses is a construction failure rather
// than an unguarded method: the runtime would refuse to install it, so learning
// that when the server starts beats learning it at installation time. The
// resolved response type is kept because a replay answers with the recorded
// bytes, which have to be decoded into the method's own output message.
func markedOperations(
	files *protoregistry.Files,
	types *protoregistry.Types,
) (map[string]protoreflect.MessageType, error) {
	operations := make(map[string]protoreflect.MessageType)
	var failure error
	files.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		services := file.Services()
		for index := range services.Len() {
			methods := services.Get(index).Methods()
			for position := range methods.Len() {
				method := methods.Get(position)
				if _, err := runnable.OperationFromMethod(method); err != nil {
					if errors.Is(err, runnable.ErrNotAnOperation) {
						continue
					}
					failure = fmt.Errorf("read the Codefly operation option: %w", err)
					return false
				}
				output, err := types.FindMessageByName(method.Output().FullName())
				if err != nil {
					failure = fmt.Errorf(
						"%w: %s answers with %s, which is not registered in this process",
						ErrInvalid, runnable.FullMethodName(method), method.Output().FullName())
					return false
				}
				operations[runnable.FullMethodName(method)] = output
			}
		}
		return true
	})
	if failure != nil {
		return nil, failure
	}
	return operations, nil
}
