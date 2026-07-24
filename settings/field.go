// Package settings provides typed access to protobuf-backed settings.
//
// Product code works exclusively with generated protobuf messages and typed
// Field values. JSON is an implementation detail of the persistence boundary.
package settings

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var ErrNilMessage = errors.New("settings message is nil")

// Field is a typed path from a generated protobuf settings message M to a
// scalar value T. Paths are resolved and validated once when the field catalog
// is initialized. Set materializes missing parent messages automatically.
type Field[M proto.Message, T any] struct {
	root         protoreflect.FullName
	path         string
	segments     []protoreflect.FieldDescriptor
	defaultValue T
	lookup       func(protoreflect.Message, protoreflect.FieldDescriptor) (T, error)
	assign       func(protoreflect.Message, protoreflect.FieldDescriptor, T) error
}

// Path returns the stable protobuf field path, using proto field names.
func (field Field[M, T]) Path() string {
	return field.path
}

// Default returns the field's configured fallback value.
func (field Field[M, T]) Default() T {
	return field.defaultValue
}

// Get returns the explicitly stored value, or the field's configured default
// when the field or any of its parent messages is absent.
func (field Field[M, T]) Get(message M) (T, error) {
	value, present, err := field.Lookup(message)
	if err != nil {
		var zero T
		return zero, err
	}
	if !present {
		return field.defaultValue, nil
	}
	return value, nil
}

// ApplyDefault writes the configured default only when the field is absent.
// It returns true when the message changed. Existing values, including
// explicit false, empty string, zero, or the zero enum, are never overwritten.
func (field Field[M, T]) ApplyDefault(message M) (bool, error) {
	_, present, err := field.Lookup(message)
	if err != nil {
		return false, err
	}
	if present {
		return false, nil
	}
	if err := field.Set(message, field.defaultValue); err != nil {
		return false, err
	}
	return true, nil
}

// Lookup returns the value and its protobuf presence. An explicit scalar zero
// (false, "", 0, or the zero enum) remains distinguishable from an unset field
// when the schema declares presence, as settings protos should.
func (field Field[M, T]) Lookup(message M) (T, bool, error) {
	var zero T
	current, err := field.rootMessage(message)
	if err != nil {
		return zero, false, err
	}
	for _, segment := range field.segments[:len(field.segments)-1] {
		if !current.Has(segment) {
			return zero, false, nil
		}
		current = current.Get(segment).Message()
	}
	leaf := field.segments[len(field.segments)-1]
	if !current.Has(leaf) {
		return zero, false, nil
	}
	value, err := field.lookup(current, leaf)
	if err != nil {
		return zero, false, fmt.Errorf("read settings field %q: %w", field.path, err)
	}
	return value, true, nil
}

// Has reports whether the complete path is explicitly present.
func (field Field[M, T]) Has(message M) (bool, error) {
	_, present, err := field.Lookup(message)
	return present, err
}

// Set writes a typed value and materializes every missing parent message.
func (field Field[M, T]) Set(message M, value T) error {
	current, err := field.rootMessage(message)
	if err != nil {
		return err
	}
	type materializedParent struct {
		message protoreflect.Message
		field   protoreflect.FieldDescriptor
		created bool
	}
	parents := make([]materializedParent, 0, len(field.segments)-1)
	for _, segment := range field.segments[:len(field.segments)-1] {
		created := !current.Has(segment)
		parent := current
		current = current.Mutable(segment).Message()
		parents = append(parents, materializedParent{
			message: parent,
			field:   segment,
			created: created,
		})
	}
	leaf := field.segments[len(field.segments)-1]
	if err := field.assign(current, leaf, value); err != nil {
		for index := len(parents) - 1; index >= 0; index-- {
			if !parents[index].created {
				break
			}
			child := parents[index].message.Get(parents[index].field).Message()
			if !messageEmpty(child) {
				break
			}
			parents[index].message.Clear(parents[index].field)
		}
		return fmt.Errorf("set settings field %q: %w", field.path, err)
	}
	return nil
}

// Clear removes a value. Empty parent messages created solely for the cleared
// path are pruned, so ProtoJSON does not persist meaningless {"parent": {}}.
func (field Field[M, T]) Clear(message M) error {
	current, err := field.rootMessage(message)
	if err != nil {
		return err
	}
	type parent struct {
		message protoreflect.Message
		field   protoreflect.FieldDescriptor
	}
	parents := make([]parent, 0, len(field.segments)-1)
	for _, segment := range field.segments[:len(field.segments)-1] {
		if !current.Has(segment) {
			return nil
		}
		parents = append(parents, parent{message: current, field: segment})
		current = current.Get(segment).Message()
	}
	current.Clear(field.segments[len(field.segments)-1])
	for index := len(parents) - 1; index >= 0; index-- {
		child := parents[index].message.Get(parents[index].field).Message()
		if !messageEmpty(child) {
			break
		}
		parents[index].message.Clear(parents[index].field)
	}
	return nil
}

func (field Field[M, T]) rootMessage(message M) (protoreflect.Message, error) {
	if isNilProto(message) {
		return nil, ErrNilMessage
	}
	root := message.ProtoReflect()
	if root.Descriptor().FullName() != field.root {
		return nil, fmt.Errorf(
			"settings field %q belongs to %s, got %s",
			field.path,
			field.root,
			root.Descriptor().FullName(),
		)
	}
	return root, nil
}

// MustString defines an optional string settings field and panics when the
// path is invalid. Field catalogs should be package-level values so schema
// mistakes fail during process initialization rather than on a request.
func MustString[M proto.Message](prototype M, path, defaultValue string) Field[M, string] {
	return mustScalarField(
		prototype,
		path,
		defaultValue,
		protoreflect.StringKind,
		func(value protoreflect.Value) (string, error) { return value.String(), nil },
		func(value string) (protoreflect.Value, error) { return protoreflect.ValueOfString(value), nil },
	)
}

// MustBool defines an optional bool settings field.
func MustBool[M proto.Message](prototype M, path string, defaultValue bool) Field[M, bool] {
	return mustScalarField(
		prototype,
		path,
		defaultValue,
		protoreflect.BoolKind,
		func(value protoreflect.Value) (bool, error) { return value.Bool(), nil },
		func(value bool) (protoreflect.Value, error) { return protoreflect.ValueOfBool(value), nil },
	)
}

// MustInt32 defines an optional int32 settings field.
func MustInt32[M proto.Message](prototype M, path string, defaultValue int32) Field[M, int32] {
	return mustScalarField(
		prototype,
		path,
		defaultValue,
		protoreflect.Int32Kind,
		func(value protoreflect.Value) (int32, error) { return int32(value.Int()), nil },
		func(value int32) (protoreflect.Value, error) {
			return protoreflect.ValueOfInt32(value), nil
		},
	)
}

// MustInt64 defines an optional int64 settings field.
func MustInt64[M proto.Message](prototype M, path string, defaultValue int64) Field[M, int64] {
	return mustScalarField(
		prototype,
		path,
		defaultValue,
		protoreflect.Int64Kind,
		func(value protoreflect.Value) (int64, error) { return value.Int(), nil },
		func(value int64) (protoreflect.Value, error) {
			return protoreflect.ValueOfInt64(value), nil
		},
	)
}

// MustEnum defines an optional enum settings field. E is the generated enum
// type (whose underlying type is int32). Set rejects values unknown to the
// field's enum descriptor.
func MustEnum[M proto.Message, E ~int32](prototype M, path string, defaultValue E) Field[M, E] {
	field, err := newField(
		prototype,
		path,
		defaultValue,
		func(descriptor protoreflect.FieldDescriptor) error {
			if descriptor.Kind() != protoreflect.EnumKind {
				return fmt.Errorf("expected enum, got %s", descriptor.Kind())
			}
			if err := requirePresence(descriptor); err != nil {
				return err
			}
			number := protoreflect.EnumNumber(defaultValue)
			if descriptor.Enum().Values().ByNumber(number) == nil {
				return fmt.Errorf(
					"default %d is not defined by %s",
					number,
					descriptor.Enum().FullName(),
				)
			}
			return nil
		},
		func(message protoreflect.Message, descriptor protoreflect.FieldDescriptor) (E, error) {
			return E(message.Get(descriptor).Enum()), nil
		},
		func(message protoreflect.Message, descriptor protoreflect.FieldDescriptor, value E) error {
			number := protoreflect.EnumNumber(value)
			if descriptor.Enum().Values().ByNumber(number) == nil {
				return fmt.Errorf("%d is not defined by %s", number, descriptor.Enum().FullName())
			}
			message.Set(descriptor, protoreflect.ValueOfEnum(number))
			return nil
		},
	)
	if err != nil {
		panic(err)
	}
	return field
}

func mustScalarField[M proto.Message, T any](
	prototype M,
	path string,
	defaultValue T,
	kind protoreflect.Kind,
	decode func(protoreflect.Value) (T, error),
	encode func(T) (protoreflect.Value, error),
) Field[M, T] {
	field, err := newField(
		prototype,
		path,
		defaultValue,
		func(descriptor protoreflect.FieldDescriptor) error {
			if descriptor.Kind() != kind {
				return fmt.Errorf("expected %s, got %s", kind, descriptor.Kind())
			}
			return requirePresence(descriptor)
		},
		func(message protoreflect.Message, descriptor protoreflect.FieldDescriptor) (T, error) {
			return decode(message.Get(descriptor))
		},
		func(message protoreflect.Message, descriptor protoreflect.FieldDescriptor, value T) error {
			encoded, err := encode(value)
			if err != nil {
				return err
			}
			message.Set(descriptor, encoded)
			return nil
		},
	)
	if err != nil {
		panic(err)
	}
	return field
}

func newField[M proto.Message, T any](
	prototype M,
	path string,
	defaultValue T,
	validate func(protoreflect.FieldDescriptor) error,
	lookup func(protoreflect.Message, protoreflect.FieldDescriptor) (T, error),
	assign func(protoreflect.Message, protoreflect.FieldDescriptor, T) error,
) (Field[M, T], error) {
	var empty Field[M, T]
	if isNilProto(prototype) {
		return empty, errors.New("settings field prototype is nil")
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return empty, errors.New("settings field path is empty")
	}
	names := strings.Split(path, ".")
	descriptor := prototype.ProtoReflect().Descriptor()
	segments := make([]protoreflect.FieldDescriptor, 0, len(names))
	for index, name := range names {
		if name == "" {
			return empty, fmt.Errorf("settings field path %q contains an empty segment", path)
		}
		field := descriptor.Fields().ByName(protoreflect.Name(name))
		if field == nil {
			return empty, fmt.Errorf(
				"settings field path %q: %s has no field %q",
				path,
				descriptor.FullName(),
				name,
			)
		}
		segments = append(segments, field)
		if index < len(names)-1 {
			if field.IsList() || field.IsMap() || field.Message() == nil {
				return empty, fmt.Errorf(
					"settings field path %q: parent %q is not a singular message",
					path,
					name,
				)
			}
			descriptor = field.Message()
		}
	}
	leaf := segments[len(segments)-1]
	if leaf.IsList() || leaf.IsMap() {
		return empty, fmt.Errorf("settings field path %q: list and map leaves are not supported", path)
	}
	if err := validate(leaf); err != nil {
		return empty, fmt.Errorf("settings field path %q: %w", path, err)
	}
	return Field[M, T]{
		root:         prototype.ProtoReflect().Descriptor().FullName(),
		path:         path,
		segments:     segments,
		defaultValue: defaultValue,
		lookup:       lookup,
		assign:       assign,
	}, nil
}

func requirePresence(descriptor protoreflect.FieldDescriptor) error {
	if !descriptor.HasPresence() {
		return fmt.Errorf(
			"field %s has no presence; declare settings scalars optional",
			descriptor.FullName(),
		)
	}
	return nil
}

func messageEmpty(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return false
	}
	empty := true
	message.Range(func(protoreflect.FieldDescriptor, protoreflect.Value) bool {
		empty = false
		return false
	})
	return empty
}

func isNilProto(message proto.Message) bool {
	if message == nil {
		return true
	}
	value := reflect.ValueOf(message)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
