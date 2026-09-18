// Package connecttransport applies Codefly effect receipts to a Connect
// handler.
//
// It is a subpackage so the receipts package itself carries no transport
// dependency, and a module serving only gRPC never compiles connect.
//
// Unlike the gRPC adapter this is a handler wrapper rather than a
// connect.Interceptor. A Connect interceptor answers with connect.AnyResponse,
// which only connect.Response[T] implements and which therefore cannot be built
// for a message type known only at run time — so an interceptor can refuse a
// call but cannot answer one from a receipt, which is the whole point. Wrapping
// is one line per handler at registration and carries no per-method logic.
package connecttransport

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/codefly-dev/sdk-go/receipts"
)

// WrapUnary guards one Connect unary handler: it requires an effect id,
// replays the receipt of an effect already committed, and refuses an effect id
// spent on a different request. A handler whose method does not carry the
// Codefly operation option is returned guarded but passes through untouched, so
// a module may wrap every handler it registers without deciding which.
func WrapUnary[Request, Response any](
	guard *receipts.Interceptor,
	procedure string,
	unary func(context.Context, *connect.Request[Request]) (*connect.Response[Response], error),
) func(context.Context, *connect.Request[Request]) (*connect.Response[Response], error) {
	return func(
		ctx context.Context,
		request *connect.Request[Request],
	) (*connect.Response[Response], error) {
		if !guard.IsOperation(procedure) {
			return unary(ctx, request)
		}
		message, isMessage := any(request.Msg).(proto.Message)
		if !isMessage {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf(
				"%s is a Codefly operation but its request is a %T, which is not a protobuf message",
				procedure, request.Msg))
		}
		effectID, err := effectIDFromHeader(request)
		if err != nil {
			return nil, refuse(err)
		}
		var (
			ran      bool
			answered *connect.Response[Response]
		)
		replayed, err := guard.Handle(ctx, procedure, effectID, message,
			func(admitted context.Context) (proto.Message, error) {
				ran = true
				answer, handlerErr := unary(admitted, request)
				if handlerErr != nil {
					return nil, handlerErr
				}
				if answer == nil {
					return nil, connect.NewError(connect.CodeInternal, fmt.Errorf(
						"%s answered with neither a response nor an error", procedure))
				}
				answered = answer
				answerMessage, isProto := any(answer.Msg).(proto.Message)
				if !isProto {
					return nil, connect.NewError(connect.CodeInternal, fmt.Errorf(
						"%s answered with a %T, which is not a protobuf message",
						procedure, answer.Msg))
				}
				return answerMessage, nil
			})
		if err != nil {
			return nil, refuse(err)
		}
		// A handler that ran owns its response headers and trailers, so its own
		// answer is returned rather than one rebuilt from the message.
		if ran {
			return answered, nil
		}
		typed, isResponse := any(replayed).(*Response)
		if !isResponse {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf(
				"%s recorded a %T, which is not the %T it answers with",
				procedure, replayed, new(Response)))
		}
		return connect.NewResponse(typed), nil
	}
}

// effectIDFromHeader reads the effect id a caller presented. Both spellings are
// accepted so a module already taking Idempotency-Key on its REST surface keeps
// one name for its callers; presenting both, or one of them twice, is ambiguous
// rather than lenient.
func effectIDFromHeader[Request any](request *connect.Request[Request]) (string, error) {
	header := request.Header()
	presented := append(
		header.Values(receipts.EffectIDHeaderName),
		header.Values(receipts.IdempotencyKeyHeaderName)...,
	)
	switch len(presented) {
	case 0:
		return "", receipts.ErrEffectIDMissing
	case 1:
		return presented[0], nil
	default:
		return "", fmt.Errorf("%w: exactly one effect id may be presented", receipts.ErrInvalid)
	}
}

func refuse(err error) error {
	switch receipts.RefusalFor(err) {
	case receipts.RefusalInvalidArgument:
		return connect.NewError(connect.CodeInvalidArgument, err)
	case receipts.RefusalFailedPrecondition:
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case receipts.RefusalInternal:
		return connect.NewError(connect.CodeInternal, err)
	default:
		return err
	}
}
