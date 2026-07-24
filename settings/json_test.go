package settings_test

import (
	"testing"

	"github.com/codefly-dev/sdk-go/settings"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestJSONCodecRoundTripsNestedPresenceUsingProtoNames(t *testing.T) {
	codec := settings.MustJSONCodec(
		func() *descriptorpb.FileDescriptorProto { return &descriptorpb.FileDescriptorProto{} },
		1024,
	)
	message := &descriptorpb.FileDescriptorProto{}
	require.NoError(t, fileSettings.GoPackage.Set(message, "example/service"))
	require.NoError(t, fileSettings.JavaMultipleFiles.Set(message, false))

	encoded, err := codec.Marshal(message)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"options": {
			"go_package": "example/service",
			"java_multiple_files": false
		}
	}`, string(encoded))

	decoded, err := codec.Unmarshal(encoded)
	require.NoError(t, err)
	value, present, err := fileSettings.JavaMultipleFiles.Lookup(decoded)
	require.NoError(t, err)
	require.True(t, present)
	require.False(t, value)
}

func TestJSONCodecTreatsEmptyStorageAsEmptyMessage(t *testing.T) {
	codec := settings.MustJSONCodec(
		func() *descriptorpb.FileDescriptorProto { return &descriptorpb.FileDescriptorProto{} },
		1024,
	)

	for _, encoded := range [][]byte{nil, {}, []byte(`{}`)} {
		decoded, err := codec.Unmarshal(encoded)
		require.NoError(t, err)
		require.NotNil(t, decoded)
		require.Nil(t, decoded.Options)
	}
}

func TestJSONCodecIgnoresRemovedUnknownFieldsOnRead(t *testing.T) {
	codec := settings.MustJSONCodec(
		func() *descriptorpb.FileDescriptorProto { return &descriptorpb.FileDescriptorProto{} },
		1024,
	)
	decoded, err := codec.Unmarshal([]byte(`{
		"name": "settings.proto",
		"removed_setting": true
	}`))
	require.NoError(t, err)
	require.Equal(t, "settings.proto", decoded.GetName())
}

func TestJSONCodecTreatsNullAsAbsentRatherThanAThirdScalarState(t *testing.T) {
	codec := settings.MustJSONCodec(
		func() *descriptorpb.FileDescriptorProto { return &descriptorpb.FileDescriptorProto{} },
		1024,
	)

	decoded, err := codec.Unmarshal([]byte(`{
		"options": {"go_package": null}
	}`))

	require.NoError(t, err)
	value, present, err := fileSettings.GoPackage.Lookup(decoded)
	require.NoError(t, err)
	require.False(t, present)
	require.Empty(t, value)
	defaulted, err := fileSettings.GoPackage.Get(decoded)
	require.NoError(t, err)
	require.Equal(t, "example/default", defaulted)
}

func TestJSONCodecRejectsMalformedAndTypeInvalidJSON(t *testing.T) {
	codec := settings.MustJSONCodec(
		func() *descriptorpb.FileDescriptorProto { return &descriptorpb.FileDescriptorProto{} },
		1024,
	)

	_, err := codec.Unmarshal([]byte(`{"options":`))
	require.ErrorContains(t, err, "unmarshal protobuf settings JSON")
	_, err = codec.Unmarshal([]byte(`{"options":{"go_package":false}}`))
	require.ErrorContains(t, err, "unmarshal protobuf settings JSON")
}

func TestJSONCodecRejectsOversizedReadsAndWrites(t *testing.T) {
	codec := settings.MustJSONCodec(
		func() *descriptorpb.FileDescriptorProto { return &descriptorpb.FileDescriptorProto{} },
		8,
	)
	_, err := codec.Unmarshal([]byte(`{"name":"too-large"}`))
	require.ErrorContains(t, err, "maximum is 8")

	name := "too-large"
	_, err = codec.Marshal(&descriptorpb.FileDescriptorProto{Name: &name})
	require.ErrorContains(t, err, "maximum is 8")
}

func TestJSONCodecRejectsInvalidFactoriesAndNilMessages(t *testing.T) {
	_, err := settings.NewJSONCodec[*descriptorpb.FileDescriptorProto](nil, 1024)
	require.Error(t, err)
	_, err = settings.NewJSONCodec(
		func() *descriptorpb.FileDescriptorProto { return nil },
		1024,
	)
	require.Error(t, err)

	codec := settings.MustJSONCodec(
		func() *descriptorpb.FileDescriptorProto { return &descriptorpb.FileDescriptorProto{} },
		1024,
	)
	var message *descriptorpb.FileDescriptorProto
	_, err = codec.Marshal(message)
	require.ErrorIs(t, err, settings.ErrNilMessage)
}
