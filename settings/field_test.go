package settings_test

import (
	"errors"
	"testing"

	"github.com/codefly-dev/sdk-go/settings"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/typepb"
)

var fileSettings = struct {
	GoPackage         settings.Field[*descriptorpb.FileDescriptorProto, string]
	JavaMultipleFiles settings.Field[*descriptorpb.FileDescriptorProto, bool]
	OptimizeFor       settings.Field[*descriptorpb.FileDescriptorProto, descriptorpb.FileOptions_OptimizeMode]
	FieldPresence     settings.Field[*descriptorpb.FileDescriptorProto, descriptorpb.FeatureSet_FieldPresence]
}{
	GoPackage: settings.MustString(
		&descriptorpb.FileDescriptorProto{},
		"options.go_package",
		"example/default",
	),
	JavaMultipleFiles: settings.MustBool(
		&descriptorpb.FileDescriptorProto{},
		"options.java_multiple_files",
		false,
	),
	OptimizeFor: settings.MustEnum(
		&descriptorpb.FileDescriptorProto{},
		"options.optimize_for",
		descriptorpb.FileOptions_SPEED,
	),
	FieldPresence: settings.MustEnum(
		&descriptorpb.FileDescriptorProto{},
		"options.features.field_presence",
		descriptorpb.FeatureSet_EXPLICIT,
	),
}

func TestNestedSetMaterializesMissingParents(t *testing.T) {
	message := &descriptorpb.FileDescriptorProto{}
	require.Nil(t, message.Options)

	require.NoError(t, fileSettings.GoPackage.Set(message, "example/service"))

	require.NotNil(t, message.Options)
	require.NotNil(t, message.Options.GoPackage)
	require.Equal(t, "example/service", message.GetOptions().GetGoPackage())
	value, present, err := fileSettings.GoPackage.Lookup(message)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, "example/service", value)
}

func TestMissingParentReturnsConfiguredDefaultWithoutMaterializing(t *testing.T) {
	message := &descriptorpb.FileDescriptorProto{}

	value, err := fileSettings.GoPackage.Get(message)
	require.NoError(t, err)
	require.Equal(t, "example/default", value)
	require.Equal(t, "example/default", fileSettings.GoPackage.Default())
	require.Nil(t, message.Options, "a read must never materialize a parent")

	_, present, err := fileSettings.GoPackage.Lookup(message)
	require.NoError(t, err)
	require.False(t, present)
}

func TestApplyDefaultMaterializesMissingParents(t *testing.T) {
	message := &descriptorpb.FileDescriptorProto{}

	changed, err := fileSettings.GoPackage.ApplyDefault(message)

	require.NoError(t, err)
	require.True(t, changed)
	require.NotNil(t, message.Options)
	require.Equal(t, "example/default", message.Options.GetGoPackage())
}

func TestApplyDefaultAcrossEveryNestedParentStateIsIdempotent(t *testing.T) {
	tests := map[string]*descriptorpb.FileDescriptorProto{
		"all parents absent": {},
		"outer parent present": {
			Options: &descriptorpb.FileOptions{},
		},
		"all parents present": {
			Options: &descriptorpb.FileOptions{
				Features: &descriptorpb.FeatureSet{},
			},
		},
	}
	for name, message := range tests {
		t.Run(name, func(t *testing.T) {
			changed, err := fileSettings.FieldPresence.ApplyDefault(message)
			require.NoError(t, err)
			require.True(t, changed)
			require.NotNil(t, message.Options)
			require.NotNil(t, message.Options.Features)
			require.NotNil(t, message.Options.Features.FieldPresence)
			require.Equal(
				t,
				descriptorpb.FeatureSet_EXPLICIT,
				message.Options.Features.GetFieldPresence(),
			)

			changed, err = fileSettings.FieldPresence.ApplyDefault(message)
			require.NoError(t, err)
			require.False(t, changed, "applying a default twice must be a no-op")
		})
	}
}

func TestApplyDefaultNeverOverwritesExplicitZeroValue(t *testing.T) {
	message := &descriptorpb.FileDescriptorProto{}
	require.NoError(t, fileSettings.JavaMultipleFiles.Set(message, false))

	changed, err := fileSettings.JavaMultipleFiles.ApplyDefault(message)

	require.NoError(t, err)
	require.False(t, changed)
	value, present, err := fileSettings.JavaMultipleFiles.Lookup(message)
	require.NoError(t, err)
	require.True(t, present)
	require.False(t, value)
}

func TestGetNeverCoalescesExplicitScalarZeroValues(t *testing.T) {
	message := &descriptorpb.FileDescriptorProto{}
	require.NoError(t, fileSettings.GoPackage.Set(message, ""))
	require.NoError(t, fileSettings.JavaMultipleFiles.Set(message, false))
	require.NoError(t, fileSettings.FieldPresence.Set(
		message,
		descriptorpb.FeatureSet_FIELD_PRESENCE_UNKNOWN,
	))

	text, present, err := fileSettings.GoPackage.Lookup(message)
	require.NoError(t, err)
	require.True(t, present)
	require.Empty(t, text)
	text, err = fileSettings.GoPackage.Get(message)
	require.NoError(t, err)
	require.Empty(t, text, "explicit empty string must not resolve to its non-empty default")

	flag, present, err := fileSettings.JavaMultipleFiles.Lookup(message)
	require.NoError(t, err)
	require.True(t, present)
	require.False(t, flag)

	enum, present, err := fileSettings.FieldPresence.Lookup(message)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, descriptorpb.FeatureSet_FIELD_PRESENCE_UNKNOWN, enum)
	enum, err = fileSettings.FieldPresence.Get(message)
	require.NoError(t, err)
	require.Equal(
		t,
		descriptorpb.FeatureSet_FIELD_PRESENCE_UNKNOWN,
		enum,
		"explicit zero enum must not resolve to its non-zero default",
	)
}

func TestSetAndClearMaterializeAndPruneMultipleMissingParents(t *testing.T) {
	message := &descriptorpb.FileDescriptorProto{}

	require.NoError(t, fileSettings.FieldPresence.Set(message, descriptorpb.FeatureSet_IMPLICIT))
	require.NotNil(t, message.Options)
	require.NotNil(t, message.Options.Features)
	require.Equal(
		t,
		descriptorpb.FeatureSet_IMPLICIT,
		message.Options.Features.GetFieldPresence(),
	)

	require.NoError(t, fileSettings.FieldPresence.Clear(message))
	require.Nil(t, message.Options, "all empty parents in the path must be pruned")
}

func TestExplicitScalarDefaultPreservesPresence(t *testing.T) {
	message := &descriptorpb.FileDescriptorProto{}

	require.NoError(t, fileSettings.JavaMultipleFiles.Set(message, false))

	value, present, err := fileSettings.JavaMultipleFiles.Lookup(message)
	require.NoError(t, err)
	require.True(t, present, "explicit false must not collapse into unset")
	require.False(t, value)
}

func TestSiblingSetSurvivesClearAndFinalClearPrunesParent(t *testing.T) {
	message := &descriptorpb.FileDescriptorProto{}
	require.NoError(t, fileSettings.GoPackage.Set(message, "example/service"))
	require.NoError(t, fileSettings.JavaMultipleFiles.Set(message, true))

	require.NoError(t, fileSettings.GoPackage.Clear(message))
	require.NotNil(t, message.Options, "parent still contains a sibling setting")
	require.True(t, message.Options.GetJavaMultipleFiles())

	require.NoError(t, fileSettings.JavaMultipleFiles.Clear(message))
	require.Nil(t, message.Options, "empty parent must be pruned")
}

func TestClearMissingNestedPathIsANoOp(t *testing.T) {
	message := &descriptorpb.FileDescriptorProto{}
	require.NoError(t, fileSettings.GoPackage.Clear(message))
	require.Nil(t, message.Options)
}

func TestClearIsIdempotentAcrossPartiallyMaterializedParents(t *testing.T) {
	message := &descriptorpb.FileDescriptorProto{
		Options: &descriptorpb.FileOptions{
			Features: &descriptorpb.FeatureSet{},
		},
	}

	require.NoError(t, fileSettings.FieldPresence.Clear(message))
	require.Nil(t, message.Options)
	require.NoError(t, fileSettings.FieldPresence.Clear(message))
	require.Nil(t, message.Options)
}

func TestClearDoesNotPruneAParentContainingUnknownWireFields(t *testing.T) {
	message := &descriptorpb.FileDescriptorProto{
		Options: &descriptorpb.FileOptions{},
	}
	message.Options.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	require.NoError(t, fileSettings.GoPackage.Set(message, "example/service"))

	require.NoError(t, fileSettings.GoPackage.Clear(message))

	require.NotNil(t, message.Options)
	require.Equal(
		t,
		[]byte{0xa0, 0x06, 0x01},
		[]byte(message.Options.ProtoReflect().GetUnknown()),
	)
}

func TestEnumSetRejectsUndefinedValues(t *testing.T) {
	message := &descriptorpb.FileDescriptorProto{}
	err := fileSettings.OptimizeFor.Set(message, descriptorpb.FileOptions_OptimizeMode(999))
	require.ErrorContains(t, err, "not defined")
	require.Nil(t, message.Options)
}

func TestEnumSetAndDefault(t *testing.T) {
	message := &descriptorpb.FileDescriptorProto{}
	value, err := fileSettings.OptimizeFor.Get(message)
	require.NoError(t, err)
	require.Equal(t, descriptorpb.FileOptions_SPEED, value)

	require.NoError(t, fileSettings.OptimizeFor.Set(message, descriptorpb.FileOptions_CODE_SIZE))
	value, present, err := fileSettings.OptimizeFor.Lookup(message)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, descriptorpb.FileOptions_CODE_SIZE, value)
}

func TestFailedNestedEnumSetRollsBackOnlyNewParents(t *testing.T) {
	javaPackage := "com.example"
	message := &descriptorpb.FileDescriptorProto{
		Options: &descriptorpb.FileOptions{
			JavaPackage: &javaPackage,
		},
	}

	err := fileSettings.FieldPresence.Set(
		message,
		descriptorpb.FeatureSet_FieldPresence(999),
	)

	require.ErrorContains(t, err, "not defined")
	require.NotNil(t, message.Options, "pre-existing outer parent must survive rollback")
	require.Equal(t, "com.example", message.Options.GetJavaPackage())
	require.Nil(t, message.Options.Features, "new empty inner parent must be rolled back")
}

func TestNilMessagesFailWithoutPanicking(t *testing.T) {
	var message *descriptorpb.FileDescriptorProto

	_, err := fileSettings.GoPackage.Get(message)
	require.ErrorIs(t, err, settings.ErrNilMessage)
	_, _, err = fileSettings.GoPackage.Lookup(message)
	require.ErrorIs(t, err, settings.ErrNilMessage)
	_, err = fileSettings.GoPackage.Has(message)
	require.ErrorIs(t, err, settings.ErrNilMessage)
	_, err = fileSettings.GoPackage.ApplyDefault(message)
	require.ErrorIs(t, err, settings.ErrNilMessage)
	require.ErrorIs(t, fileSettings.GoPackage.Set(message, "value"), settings.ErrNilMessage)
	require.ErrorIs(t, fileSettings.GoPackage.Clear(message), settings.ErrNilMessage)
}

func TestInvalidCatalogPathsFailAtInitialization(t *testing.T) {
	require.Panics(t, func() {
		settings.MustString(&descriptorpb.FileDescriptorProto{}, "options.missing", "")
	})
	require.Panics(t, func() {
		settings.MustString(&descriptorpb.FileDescriptorProto{}, "name.child", "")
	})
	require.Panics(t, func() {
		// name is a proto3 scalar without presence.
		settings.MustString(&typepb.Type{}, "name", "")
	})
	require.Panics(t, func() {
		settings.MustEnum(
			&descriptorpb.FileDescriptorProto{},
			"options.optimize_for",
			descriptorpb.FileOptions_OptimizeMode(999),
		)
	})
}

func TestErrNilMessageIsStable(t *testing.T) {
	require.True(t, errors.Is(settings.ErrNilMessage, settings.ErrNilMessage))
}
