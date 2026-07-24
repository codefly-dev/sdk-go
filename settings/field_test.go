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

func TestNilMessagesFailWithoutPanicking(t *testing.T) {
	var message *descriptorpb.FileDescriptorProto

	_, err := fileSettings.GoPackage.Get(message)
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
}

func TestErrNilMessageIsStable(t *testing.T) {
	require.True(t, errors.Is(settings.ErrNilMessage, settings.ErrNilMessage))
}
