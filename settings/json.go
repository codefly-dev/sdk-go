package settings

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const DefaultMaximumJSONBytes = 128 * 1024

// JSONCodec is the only conversion boundary between typed protobuf settings
// and their JSONB representation. UseProtoNames keeps persisted keys stable
// across Go and TypeScript, while DiscardUnknown allows safe rolling schema
// removal without deleting older keys from the database.
type JSONCodec[M proto.Message] struct {
	newMessage func() M
	maximum    int
}

func NewJSONCodec[M proto.Message](newMessage func() M, maximumBytes int) (*JSONCodec[M], error) {
	if newMessage == nil {
		return nil, errors.New("settings message factory is required")
	}
	if maximumBytes <= 0 {
		maximumBytes = DefaultMaximumJSONBytes
	}
	message := newMessage()
	if isNilProto(message) {
		return nil, errors.New("settings message factory returned nil")
	}
	return &JSONCodec[M]{newMessage: newMessage, maximum: maximumBytes}, nil
}

func MustJSONCodec[M proto.Message](newMessage func() M, maximumBytes int) *JSONCodec[M] {
	codec, err := NewJSONCodec(newMessage, maximumBytes)
	if err != nil {
		panic(err)
	}
	return codec
}

func (codec *JSONCodec[M]) Marshal(message M) ([]byte, error) {
	if codec == nil || codec.newMessage == nil {
		return nil, errors.New("settings JSON codec is not configured")
	}
	if isNilProto(message) {
		return nil, ErrNilMessage
	}
	encoded, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("marshal protobuf settings as JSON: %w", err)
	}
	if len(encoded) > codec.maximum {
		return nil, fmt.Errorf(
			"protobuf settings JSON is %d bytes; maximum is %d",
			len(encoded),
			codec.maximum,
		)
	}
	return encoded, nil
}

func (codec *JSONCodec[M]) Unmarshal(encoded []byte) (M, error) {
	var zero M
	if codec == nil || codec.newMessage == nil {
		return zero, errors.New("settings JSON codec is not configured")
	}
	if len(encoded) > codec.maximum {
		return zero, fmt.Errorf(
			"protobuf settings JSON is %d bytes; maximum is %d",
			len(encoded),
			codec.maximum,
		)
	}
	message := codec.newMessage()
	if isNilProto(message) {
		return zero, errors.New("settings message factory returned nil")
	}
	if len(encoded) == 0 {
		encoded = []byte("{}")
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(encoded, message); err != nil {
		return zero, fmt.Errorf("unmarshal protobuf settings JSON: %w", err)
	}
	return message, nil
}
