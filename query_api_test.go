package codefly_test

import (
	"reflect"
	"testing"

	codefly "github.com/codefly-dev/sdk-go"
)

func TestQueryDoesNotExposeDefaultNetworkAPI(t *testing.T) {
	query := reflect.TypeFor[codefly.Query]()
	// The compiled pointer method set includes value-receiver and promoted
	// methods, regardless of signature or implementation (including no-ops).
	if _, exists := reflect.PointerTo(query).MethodByName("WithDefaultNetwork"); exists {
		t.Fatal("Query.WithDefaultNetwork must remain deleted, including inert methods")
	}
	// A callable field would restore the same consumer-facing selector without
	// adding a method. FieldByName also includes promoted fields.
	if _, exists := query.FieldByName("WithDefaultNetwork"); exists {
		t.Fatal("Query.WithDefaultNetwork must not return as a field")
	}
}
