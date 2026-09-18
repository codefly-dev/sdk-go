// Package grpctransport applies Codefly effect receipts to a gRPC server.
//
// It is a subpackage so the receipts package itself carries no transport
// dependency, and a module serving only Connect never compiles grpc.
package grpctransport

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/codefly-dev/sdk-go/receipts"
)

// UnaryServerInterceptor guards every method carrying the Codefly operation
// option: it requires an effect id, replays the receipt of an effect already
// committed, and refuses an effect id spent on a different request. A method
// without the option passes through untouched.
func UnaryServerInterceptor(guard *receipts.Interceptor) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		request any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if !guard.IsOperation(info.FullMethod) {
			return handler(ctx, request)
		}
		message, isMessage := request.(proto.Message)
		if !isMessage {
			return nil, status.Errorf(codes.Internal,
				"%s is a Codefly operation but its request is a %T, which is not a protobuf message",
				info.FullMethod, request)
		}
		effectID, err := effectIDFromIncoming(ctx)
		if err != nil {
			return nil, refuse(err)
		}
		response, err := guard.Handle(ctx, info.FullMethod, effectID, message,
			func(admitted context.Context) (proto.Message, error) {
				answer, handlerErr := handler(admitted, request)
				if handlerErr != nil {
					return nil, handlerErr
				}
				answered, isProto := answer.(proto.Message)
				if !isProto {
					return nil, status.Errorf(codes.Internal,
						"%s answered with a %T, which is not a protobuf message",
						info.FullMethod, answer)
				}
				return answered, nil
			})
		if err != nil {
			return nil, refuse(err)
		}
		return response, nil
	}
}

// effectIDFromIncoming reads the effect id a caller presented. Both spellings
// are accepted so a module already taking Idempotency-Key on its REST surface
// keeps one name for its callers; presenting both, or one of them twice, is
// ambiguous rather than lenient.
func effectIDFromIncoming(ctx context.Context) (string, error) {
	incoming, present := metadata.FromIncomingContext(ctx)
	if !present {
		return "", receipts.ErrEffectIDMissing
	}
	presented := append(
		incoming.Get(receipts.EffectIDHeaderName),
		incoming.Get(receipts.IdempotencyKeyHeaderName)...,
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
		return status.Error(codes.InvalidArgument, err.Error())
	case receipts.RefusalFailedPrecondition:
		return status.Error(codes.FailedPrecondition, err.Error())
	case receipts.RefusalInternal:
		return status.Error(codes.Internal, err.Error())
	default:
		return err
	}
}
