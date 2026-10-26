package workcontext

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
)

// THE CODEC RULE, DECIDED BY go/types.
//
// The syntactic version answered with a SPELLING where the question was a
// KIND, and a reviewer walked six probes through the gap, each compiled and
// each decoding a real capability:
//
//	func into[M proto.Message](raw []byte, m M) error   // resolved to "M"
//	type r6msg interface{ proto.Message }               // resolved to "r6msg"
//	type r6carrier = proto.Message                      // resolved to "r6carrier"
//	reflect.ValueOf(proto.Unmarshal).Call(…)            // resolved to "[]reflect#Value"
//	r6use(proto.Unmarshal)(raw, c)                      // a closure, no call to read
//	func (r6other) Handle(…) { proto.Unmarshal(…) }      // allowlisted BY NAME
//
// None of those is a type name question. "Is this argument an interface or a
// type parameter", "is this codec being used as a value rather than called",
// and "is this the function my allowlist named, or another one spelled the
// same" are all questions about objects and types, and go/types answers all
// three. The allowlist is keyed on *types.Func identity now, so a second
// method named Handle on a new type is a different object and is refused.
//
// What this still does NOT reach: a hand-written wire walk with no codec at
// all. That is the irreducible residue and it is closed by review — see the
// note on allowedImports.

// codecFunctions are the functions and methods that move a message between
// bytes and a value, by PACKAGE PATH and name.
//
// The set is closed by the import allowlist: a codec in a package neither
// module may import cannot be reached, which is why protodelim and the gRPC
// codec registry are absent here and refused there instead. Two rules, one
// each for the two halves of the question.
var codecFunctions = map[string][]string{
	"encoding/asn1": {"Marshal", "MarshalWithParams", "Unmarshal", "UnmarshalWithParams"},
	"google.golang.org/protobuf/proto": {
		"Marshal", "Unmarshal", "MarshalOptions", "UnmarshalOptions",
	},
	"google.golang.org/protobuf/encoding/protojson": {
		"Marshal", "Unmarshal", "MarshalOptions", "UnmarshalOptions",
	},
	"encoding/json": {
		"Marshal", "MarshalIndent", "Unmarshal",
		"NewEncoder", "NewDecoder", "Encode", "Decode",
	},
}

// envelopeDecoders are the base64 methods that OPEN an envelope, by package and
// name, resolved as objects.
//
// The syntactic rule required the receiver to be written as a selector —
// `base64.RawURLEncoding.DecodeString(…)` — so one assignment walked past it:
//
//	var payloadEncoding = base64.RawURLEncoding
//	func openPayload(s string) ([]byte, error) { return payloadEncoding.DecodeString(s) }
//
// in the one file allowed to reach for base64. go/types answers the method's
// OBJECT regardless of how the receiver was spelled, which is the same
// correction the codec rule needed and for the same reason: a spelling was
// standing in for a kind.
var envelopeDecodeMethods = map[string][]string{
	"encoding/base64": {"Decode", "DecodeString", "AppendDecode", "NewDecoder"},
}

// codecIndirectionObjects are the functions that legitimately apply a codec to
// a value whose type is not statically known, keyed on PACKAGE PATH and the
// function's own name — which with go/types identifies the object rather than
// the spelling.
//
// Four, all taking an interface by design: three in receipts, whose subject is
// a caller's own request and response messages, and the runtime's own
// configuration documents, decoded into a caller's destination. The syntactic
// gate's comment said "three" for two rounds after the fourth was added, which
// is why the count is checked rather than written: see the test below.
var codecIndirectionObjects = map[string][]string{
	// package path -> "Receiver.Function", or "Function" for a plain function.
	"github.com/codefly-dev/sdk-go/receipts": {
		"RequestDigest", "Record", "Interceptor.Handle",
	},
	"github.com/codefly-dev/sdk-go": {"decodeDocument"},
}

// TestNoCodecTouchesACapabilityByType is the type-checked codec rule over both
// modules.
func TestNoCodecTouchesACapabilityByType(t *testing.T) {
	var findings []string
	for _, module := range loadModules(t) {
		for _, loaded := range module.packages {
			if loaded.TypesInfo == nil {
				continue
			}
			for _, file := range loaded.Syntax {
				path := module.relative(loaded, file)
				if path == "" || strings.HasSuffix(path, "_test.go") {
					continue
				}
				findings = append(findings, inspectCodecUses(loaded, file, path)...)
			}
		}
	}
	require.Empty(t, findings, "%s", strings.Join(findings, "\n\n"))
}

// inspectCodecUses is the rule over one type-checked file.
func inspectCodecUses(loaded *packages.Package, file *ast.File, path string) []string {
	var findings []string
	findings = append(findings, inspectHandWrittenProtoMessages(loaded, file, path)...)
	// THE Fun POSITION, and the identifier inside it. ast.Inspect descends into
	// a SelectorExpr, so recording only call.Fun left `Marshal` — the Sel of a
	// perfectly ordinary `json.Marshal(x)` — looking like a codec mentioned
	// without being called. Both are recorded.
	calls := map[ast.Expr]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		calls[call.Fun] = true
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
			calls[selector.Sel] = true
			// proto.MarshalOptions{…}.Marshal: the receiver is itself a
			// composite literal whose Type names the codec.
			if literal, ok := selector.X.(*ast.CompositeLit); ok {
				calls[literal.Type] = true
				if inner, ok := literal.Type.(*ast.SelectorExpr); ok {
					calls[inner.Sel] = true
				}
			}
			if inner, ok := selector.X.(*ast.SelectorExpr); ok {
				calls[inner.Sel] = true
			}
		}
		return true
	})

	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		function := codecFunctionOf(loaded, call.Fun)
		if function == nil {
			return true
		}
		for _, argument := range call.Args {
			kind := loaded.TypesInfo.TypeOf(argument)
			if kind == nil {
				continue
			}
			// A NAMED CAPABILITY IS ANSWERED FIRST, by its row. The
			// interface walk below is transitive now, and a generated
			// message's own internals must not be what decides a call that a
			// row already permits.
			if named := capabilityWithin(kind, map[types.Type]bool{}); named != "" {
				if permittedCapabilityCodec(path, named) {
					continue
				}
				findings = append(findings, fmt.Sprintf(
					"%s applies %s to %s, which is or contains %s.\n"+
						"A Work Context message passes through a codec only where a row names it.\n"+
						"Reading one off the wire is corework.Decode's job, and it returns the claims\n"+
						"it decoded. This catches it THROUGH a field as well: a *Claims embedded in\n"+
						"mintRequest put a whole capability on the wire through a row written for two\n"+
						"strings, and the alias lived in another file, so no syntactic rule could see it.",
					path, function.FullName(), kind, named))
				continue
			}
			// A TYPE PARAMETER OR AN INTERFACE IS NOT A TYPE, it is a
			// promise that one will turn up at the call site — which is
			// exactly where a capability turned up in seven separate probes,
			// the last of them wrapped in a concrete struct.
			if isUnknownToTheGate(kind) {
				if permittedIndirection(loaded, file, call.Pos()) {
					continue
				}
				findings = append(findings, fmt.Sprintf(
					"%s applies %s to a value of type %s, which is an interface or a type parameter.\n"+
						"A codec whose argument's type is not known statically can be handed a\n"+
						"capability at any call site, and six compiled probes did exactly that —\n"+
						"a generic `func into[M proto.Message]`, an embedded interface, an alias of\n"+
						"proto.Message, a reflect.Call, a closure and a descriptor-built message.\n"+
						"The legitimate indirections are %v, keyed on the function's own object.",
					path, function.FullName(), kind, codecIndirectionObjects))
				continue
			}
		}
		return true
	})

	// A CAPABILITY HANDED INTO ONE OF THE PERMITTED INDIRECTIONS.
	//
	// The indirections exist because those four functions take an interface by
	// design, and the exemption was granted at the CODEC call inside them. But
	// nothing looked at their CALLERS, so
	//
	//	decodeDocument(name, payload, &basev0.WorkContextV1{})
	//
	// reached a json.Unmarshal of a capability through an exemption written for
	// the runtime's own configuration documents — and configuration_document.go
	// decodes into the generated struct, whose json tags are snake_case, which
	// IS the deleted format. The hole was named at 04e93c0 as needing go/types;
	// having go/types did not close it, because the rule was still only about
	// codec calls.
	//
	// There is no row here and there is not going to be one: these four take a
	// caller's own messages, never a capability.
	// BASE64 MAY ENCODE AND MAY NEVER DECODE, by object. The file allowed to
	// build a cache key is the only file that may reach base64 at all, and
	// decoding there plus a proto.Unmarshal is the whole of a second parser.
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		object, ok := loaded.TypesInfo.Uses[selector.Sel]
		if !ok {
			return true
		}
		method, ok := object.(*types.Func)
		if !ok || method.Pkg() == nil {
			return true
		}
		if !slices.Contains(envelopeDecodeMethods[method.Pkg().Path()], method.Name()) {
			return true
		}
		findings = append(findings, fmt.Sprintf(
			"%s calls %s.\n"+
				"This file may ENCODE with base64 — it builds a cache key — and may never\n"+
				"DECODE. base64 decoding plus proto.Unmarshal is the entire second parser this\n"+
				"module deleted; corework.Decode opens the envelope and hands back the claims.\n"+
				"Resolved as an OBJECT, so assigning the encoding to a variable first does not\n"+
				"change the answer.",
			path, method.FullName()))
		return true
	})

	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		indirection := indirectionFunctionOf(loaded, call.Fun)
		if indirection == "" {
			return true
		}
		for _, argument := range call.Args {
			kind := loaded.TypesInfo.TypeOf(argument)
			named := capabilityWithin(kind, map[types.Type]bool{})
			if named == "" {
				continue
			}
			findings = append(findings, fmt.Sprintf(
				"%s passes %s, which is or contains %s, into %s.\n"+
					"That function is on the codec-indirection allowlist because it takes an\n"+
					"interface BY DESIGN — a caller's own request, response or configuration\n"+
					"document. The exemption is for the codec call inside it, not for handing it a\n"+
					"capability: decodeDocument json-decodes into its destination, and a\n"+
					"WorkContextV1's json tags are snake_case, which is the format this module\n"+
					"deleted. corework.Decode reads a capability.",
				path, kind, named, indirection))
		}
		return true
	})

	// A CODEC USED AS A VALUE. `reflect.ValueOf(proto.Unmarshal)` and
	// `r6use(proto.Unmarshal)` both reach a decode with no call for the rule
	// above to read, and both were green. Nothing in either module passes a
	// codec around, so the reference itself is the finding.
	ast.Inspect(file, func(node ast.Node) bool {
		expression, ok := node.(ast.Expr)
		if !ok || calls[expression] {
			return true
		}
		switch expression.(type) {
		case *ast.Ident, *ast.SelectorExpr:
		default:
			return true
		}
		function := codecFunctionOf(loaded, expression)
		if function == nil {
			return true
		}
		findings = append(findings, fmt.Sprintf(
			"%s mentions %s without calling it.\n"+
				"A codec passed as a value reaches a decode that no call-site rule can read:\n"+
				"reflect.ValueOf(proto.Unmarshal).Call(…) and a closure taking proto.Unmarshal were\n"+
				"both compiled, both decoded a real capability, and both passed. Nothing here needs\n"+
				"to pass a codec around.",
			path, function.FullName()))
		return true
	})
	return findings
}

// indirectionFunctionOf names the permitted indirection an expression calls, or
// "". It is the same (package, Receiver.Function) key the exemption uses, so
// the two cannot disagree about which function is meant.
func indirectionFunctionOf(loaded *packages.Package, expression ast.Expr) string {
	var identifier *ast.Ident
	switch typed := expression.(type) {
	case *ast.Ident:
		identifier = typed
	case *ast.SelectorExpr:
		identifier = typed.Sel
	default:
		return ""
	}
	object, ok := loaded.TypesInfo.Uses[identifier]
	if !ok {
		object = loaded.TypesInfo.Defs[identifier]
	}
	function, ok := object.(*types.Func)
	if !ok || function.Pkg() == nil {
		return ""
	}
	qualified := function.Name()
	if signature, ok := function.Type().(*types.Signature); ok && signature.Recv() != nil {
		receiver := signature.Recv().Type()
		if pointer, ok := types.Unalias(receiver).(*types.Pointer); ok {
			receiver = pointer.Elem()
		}
		named, ok := types.Unalias(receiver).(*types.Named)
		if !ok || named.Obj() == nil {
			return ""
		}
		qualified = named.Obj().Name() + "." + function.Name()
	}
	if slices.Contains(codecIndirectionObjects[function.Pkg().Path()], qualified) {
		return function.Pkg().Path() + "." + qualified
	}
	return ""
}

// inspectHandWrittenProtoMessages refuses a hand-written ProtoReflect method —
// which is to say, any type in this repository that claims to BE a protobuf
// message.
//
// THE PREVIOUS FIX CLOSED A SUBCLASS AND LEFT THE CLASS OPEN. Making the
// interface walk transitive caught a struct carrying an interface; it does not
// catch a concrete FUNCTION type, because carriesAnInterface does not descend
// into a *types.Signature and capabilityWithin finds nothing in a func-typed
// field. Executed, decoding a real core-minted token:
//
//	type r8thunk func() protoreflect.Message
//	func (f r8thunk) ProtoReflect() protoreflect.Message { return f() }
//	proto.Unmarshal(raw, r8thunk(claims.ProtoReflect))
//
// and the same through a struct with a func field. Both passed all three Go
// gates, lint and the sweep.
//
// Chasing the shape was the mistake. A wrapper can be a struct, a func, a
// defined slice, a map, a channel — anything with a method set — so a rule
// written about shapes is a rule that is behind by one shape, which is the
// denylist failure in another costume. What every one of them must have is a
// ProtoReflect method, because that IS the protobuf contract: it is how the
// capability gets reached, and no amount of indirection avoids it.
//
// So the rule is about the method, not the shape. A protobuf message is
// GENERATED, by protoc, in the repository that owns the .proto — core. This
// repository writes none, has zero today, and a hand-written one is a type
// pretending to be a message, which is the second implementation in the one
// form that cannot be disguised.
func inspectHandWrittenProtoMessages(
	loaded *packages.Package, file *ast.File, path string,
) []string {
	var findings []string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Recv == nil || function.Name == nil {
			continue
		}
		if !slices.Contains(protoMessageMethods, function.Name.Name) {
			continue
		}
		receiver := "a local type"
		if object, ok := loaded.TypesInfo.Defs[function.Name].(*types.Func); ok {
			receiver = object.FullName()
		}
		findings = append(findings, fmt.Sprintf(
			"%s hand-writes %s on %s.\n"+
				"A protobuf message is GENERATED, by protoc, in the repository that owns the\n"+
				"schema — core. A hand-written %s makes a local type into a proto.Message, which\n"+
				"is how a capability reaches a codec with no interface and no capability type\n"+
				"anywhere in the signature: a func type, a struct with a func field, a defined\n"+
				"slice, anything with a method set. Chasing the shapes is a denylist; the method\n"+
				"is the contract, so the method is the rule.",
			path, function.Name.Name, receiver, function.Name.Name))
	}
	return findings
}

// protoMessageMethods are the methods that make a type a protobuf message to
// the codecs. ProtoReflect is the v2 contract and Reset/String/ProtoMessage are
// the v1 one, which proto.Unmarshal still accepts through protoimpl.
var protoMessageMethods = []string{"ProtoReflect", "ProtoMessage"}

// codecFunctionOf resolves an expression to a codec function's OBJECT, or nil.
func codecFunctionOf(loaded *packages.Package, expression ast.Expr) *types.Func {
	var identifier *ast.Ident
	switch typed := expression.(type) {
	case *ast.Ident:
		identifier = typed
	case *ast.SelectorExpr:
		identifier = typed.Sel
	default:
		return nil
	}
	object, ok := loaded.TypesInfo.Uses[identifier]
	if !ok {
		object = loaded.TypesInfo.Defs[identifier]
	}
	function, ok := object.(*types.Func)
	if !ok || function.Pkg() == nil {
		return nil
	}
	named, ok := codecFunctions[function.Pkg().Path()]
	if !ok {
		return nil
	}
	for _, name := range named {
		if function.Name() == name {
			return function
		}
	}
	// A composite-literal codec — proto.MarshalOptions{}.Marshal — arrives as
	// the METHOD, whose package is the same, so the receiver's own name is
	// checked too.
	if signature, ok := function.Type().(*types.Signature); ok && signature.Recv() != nil {
		receiver := signature.Recv().Type()
		if pointer, ok := receiver.(*types.Pointer); ok {
			receiver = pointer.Elem()
		}
		if receiverNamed, ok := receiver.(*types.Named); ok {
			for _, name := range named {
				if receiverNamed.Obj().Name() == name {
					return function
				}
			}
		}
	}
	return nil
}

// isUnknownToTheGate reports whether a type says "whatever the caller passes"
// — an interface, a type parameter, or anything that CONTAINS one.
//
// It had an explicit *types.TypeParam branch, and a mutation showed the branch
// was dead: a type parameter's underlying type IS its constraint interface, so
// types.IsInterface already returns true for one.
//
// THE "CONTAINS" PART IS THE ROUND-SEVEN BLOCKER, and it needed no handwritten
// anything:
//
//	type envelopeTarget struct{ proto.Message }
//
//	func decode(raw []byte, dst *basev0.WorkContextV1) error {
//	    return proto.Unmarshal(raw, &envelopeTarget{Message: dst})
//	}
//
// The wrapper is CONCRETE, so checking the outer type answered "known"; the
// capability walk descended into it, reached `proto.Message`, and had no
// interface case so returned nothing; and the syntactic gate resolved
// `envelopeTarget` as neither a capability nor a codec interface. Three checks,
// three misses, and the embedded interface's promoted ProtoReflect delegates
// to the capability — so this is the ordinary protobuf decoder, which the
// documented handwritten-wire-walk exception does not cover.
//
// A struct carrying an interface IS an interface as far as a codec is
// concerned: what it holds is chosen at the call site. So the walk is
// transitive, and the only thing that makes such an argument acceptable is one
// of the named indirections.
func isUnknownToTheGate(kind types.Type) bool {
	return carriesAnInterface(kind, map[types.Type]bool{})
}

// carriesAnInterface walks a type for an interface or a type parameter, through
// pointers, slices, arrays, maps, aliases and STRUCT FIELDS — embedded ones
// included, which is where the promoted codec interface hides.
//
// It does not descend into CORE's own types: a generated message's internal
// state is core's business, and a capability reached through a row is answered
// by capabilityWithin before this is consulted.
func carriesAnInterface(kind types.Type, seen map[types.Type]bool) bool {
	if kind == nil || seen[kind] {
		return false
	}
	seen[kind] = true
	switch typed := types.Unalias(kind).(type) {
	case *types.Interface:
		return true
	case *types.TypeParam:
		return true
	case *types.Pointer:
		return carriesAnInterface(typed.Elem(), seen)
	case *types.Slice:
		return carriesAnInterface(typed.Elem(), seen)
	case *types.Array:
		return carriesAnInterface(typed.Elem(), seen)
	case *types.Map:
		return carriesAnInterface(typed.Elem(), seen)
	case *types.Named:
		if types.IsInterface(typed) {
			return true
		}
		if strings.HasPrefix(packagePathOf(typed.Obj()), coreModulePath) {
			return false
		}
		return carriesAnInterface(typed.Underlying(), seen)
	case *types.Struct:
		for index := range typed.NumFields() {
			if carriesAnInterface(typed.Field(index).Type(), seen) {
				return true
			}
		}
	}
	return false
}

// capabilityWithin names the capability a type is, or carries in a field, or
// "".
//
// Through pointers, slices, arrays, maps, aliases and STRUCT FIELDS, embedded
// ones included. `seen` stops the walk on protobuf's recursive messages.
func capabilityWithin(kind types.Type, seen map[types.Type]bool) string {
	if kind == nil || seen[kind] {
		return ""
	}
	seen[kind] = true
	switch typed := types.Unalias(kind).(type) {
	case *types.Pointer:
		return capabilityWithin(typed.Elem(), seen)
	case *types.Slice:
		return capabilityWithin(typed.Elem(), seen)
	case *types.Array:
		return capabilityWithin(typed.Elem(), seen)
	case *types.Map:
		return capabilityWithin(typed.Elem(), seen)
	case *types.Named:
		object := typed.Obj()
		if object != nil && object.Pkg() != nil {
			if isCapabilityType(object.Pkg().Path() + "#" + object.Name()) {
				return object.Pkg().Path() + "#" + object.Name()
			}
		}
		// A STRUCT CARRYING ONE, walked into. The exception is core's own
		// packages: a capability's sub-messages, and the fields of a Verified,
		// are core's business and finding one there says nothing about this
		// repository.
		//
		// Written as "only walk into types under this repository's module
		// path" first, which was wrong in a way the probes caught: a probe's
		// package is not under that path, so the rule could not be driven at
		// all and the test would have passed having walked nothing.
		if strings.HasPrefix(packagePathOf(object), coreModulePath) {
			return ""
		}
		return capabilityWithin(typed.Underlying(), seen)
	case *types.Struct:
		for index := range typed.NumFields() {
			if named := capabilityWithin(typed.Field(index).Type(), seen); named != "" {
				return named
			}
		}
	}
	return ""
}

func packagePathOf(object *types.TypeName) string {
	if object == nil || object.Pkg() == nil {
		return ""
	}
	return object.Pkg().Path()
}

// capabilityCodecRows is every (file, capability type) pair a codec may touch.
//
// One. cache_partition.go proto-marshals a WorkScopeV1 to build a cache key,
// and `Work`-prefixed under core is what makes a type a capability — a prefix,
// so a message core adds later is covered the day it exists, at the cost of
// this one honest use needing a row.
var capabilityCodecRows = map[string][]string{
	"workcontext/cache_partition.go": {basev0Path + "#WorkScopeV1"},
}

func permittedCapabilityCodec(path string, named string) bool {
	return slices.Contains(capabilityCodecRows[path], named)
}

// permittedIndirection reports whether the function enclosing pos is one of
// the named indirections, BY OBJECT.
//
// This is what closes the allowlist's last hole: it used to be keyed on the
// enclosing function's NAME, so a reviewer declared a second method called
// Handle on a new type, put a decode of a real capability inside it, and was
// permitted. An object carries the package and the receiver; a name carries
// neither.
func permittedIndirection(loaded *packages.Package, file *ast.File, pos token.Pos) bool {
	path, key := indirectionKeyAt(loaded, file, pos)
	if key == "" {
		return false
	}
	return slices.Contains(codecIndirectionObjects[path], key)
}

// indirectionKeyAt names the function enclosing pos as the allowlist keys it:
// the package path, and "Receiver.Function" or "Function".
//
// Returned rather than compared inside permittedIndirection so a probe can
// assert the KEY. Asserting only the decision let two mutations survive —
// dropping the receiver from the key, and writing the row name-only, each
// harmless alone and a complete bypass together. That is the coupled-edit
// shape that has now survived three times in this repository, so the rule is
// pinned at the rule.
func indirectionKeyAt(loaded *packages.Package, file *ast.File, pos token.Pos) (string, string) {
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		if pos < function.Body.Pos() || pos > function.Body.End() {
			continue
		}
		object, ok := loaded.TypesInfo.Defs[function.Name].(*types.Func)
		if !ok || object.Pkg() == nil {
			return "", ""
		}
		// THE RECEIVER IS PART OF THE NAME. A method is permitted only on the
		// type the row was written for, so a second method called Handle on a
		// new type — which a reviewer wrote, with a decode of a real
		// capability inside it — is a different object and is refused.
		if function.Recv == nil {
			return object.Pkg().Path(), object.Name()
		}
		receiver := loaded.TypesInfo.TypeOf(function.Recv.List[0].Type)
		if pointer, ok := types.Unalias(receiver).(*types.Pointer); ok {
			receiver = pointer.Elem()
		}
		named, ok := types.Unalias(receiver).(*types.Named)
		if !ok || named.Obj() == nil {
			return "", ""
		}
		return object.Pkg().Path(), named.Obj().Name() + "." + object.Name()
	}
	return "", ""
}

// DELETED: TestTheCodecRuleAnswersAboutKindsNotSpellings.
//
// Its name said it drove each probe shape at the predicate and its body
// asserted one call to isCapabilityType — a grand name over a tautology, which
// a review doubted and was right to. What it claimed is done by
// TestTheCodecRuleRefusesEveryShapeThatPassedBefore, which drives every shape
// against type-checked source, and by the per-rule tests beside it. A stub kept
// for its name is worse than no test: it reads as coverage.

// typeCheckedProbe type-checks a probe against the REAL dependency types.
//
// No temporary module and no network: packages.Load has already type-checked
// both modules and everything they import, so those *types.Package values are
// handed to go/types as an importer. The probe is then checked exactly as
// shipped code would be, which is what makes "this compiles and decodes a real
// capability" a thing a committed test can assert instead of a thing a review
// has to execute in a throwaway worktree.
func typeCheckedProbe(t *testing.T, source string) (*packages.Package, *ast.File) {
	return typeCheckedProbeIn(t, "probe", source)
}

// typeCheckedProbeIn checks a probe UNDER A GIVEN PACKAGE PATH, which is what
// lets the indirection allowlist be driven: it is keyed on the package and the
// receiver, and a probe compiled as package "probe" is refused by the package
// key before the receiver key is ever consulted. A mutation showed exactly
// that — removing the receiver from the key changed nothing, because no probe
// had reached it.
func typeCheckedProbeIn(t *testing.T, packagePath string, source string) (*packages.Package, *ast.File) {
	t.Helper()
	importer := probeImporter(t)
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "probe.go", source, parser.SkipObjectResolution)
	require.NoError(t, err, "the probe does not parse, so it is not a bypass of anything")

	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{},
		Defs:  map[*ast.Ident]types.Object{},
		Uses:  map[*ast.Ident]types.Object{},
	}
	config := &types.Config{Importer: importer}
	_, err = config.Check(packagePath, fileSet, []*ast.File{file}, info)
	require.NoError(t, err, "the probe does not type-check, so it is not a bypass of anything")

	return &packages.Package{Fset: fileSet, Syntax: []*ast.File{file}, TypesInfo: info}, file
}

// loadedTypeImporter is every package both modules already depend on, as types.
type loadedTypeImporter map[string]*types.Package

func (i loadedTypeImporter) Import(path string) (*types.Package, error) {
	if found, ok := i[path]; ok {
		return found, nil
	}
	return nil, fmt.Errorf("probe imports %q, which neither module depends on; "+
		"the import allowlist is the rule for that", path)
}

func probeImporter(t *testing.T) loadedTypeImporter {
	t.Helper()
	importer := loadedTypeImporter{}
	for _, module := range loadModules(t) {
		packages.Visit(module.packages, nil, func(one *packages.Package) {
			if one.Types != nil && one.Types.Complete() {
				importer[one.PkgPath] = one.Types
			}
		})
	}
	require.Contains(t, importer, "google.golang.org/protobuf/proto",
		"the probe importer is empty, so every probe below would fail to type-check "+
			"for the wrong reason and the test would pass having asserted nothing")
	return importer
}

// EVERY PROBE THE EXECUTED REVIEW COMPILED AND RAN, at the rule.
//
// Each of these decoded a real WorkContextV1 minted by core's Authority and
// printed its tenant, against the previous revision of this gate, with both
// gates green. They are not readings of the code.
func TestTheCodecRuleRefusesEveryShapeThatPassedBefore(t *testing.T) {
	const preamble = `package probe

import (
	"encoding/asn1"
	"encoding/json"
	"reflect"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// Sinks, so every probe shares one import block without "imported and not
// used". None is a codec use, so none can be the finding.
var (
	_ asn1.RawValue
	_ = reflect.TypeOf
	_ protoreflect.Message
	_ = basev0.File_codefly_base_v0_work_context_proto
	_ = json.Valid
	// proto.Size is not a codec, so naming it keeps the import live for every
	// probe without being the finding in any of them.
	_ = proto.Size
)

`
	for name, probe := range map[string]struct {
		source string
		says   string
	}{
		"ASN1 decoding a capability": {
			source: `func into(raw []byte, c *basev0.WorkContextV1) { _, _ = asn1.Unmarshal(raw, c) }`,
			says:   "which is or contains",
		},
		"ASN1 decoder passed as a value": {
			source: `var decode = asn1.Unmarshal`,
			says:   "without calling it",
		},
		// R1: a type parameter. Resolved to the spelling "M".
		"a generic codec wrapper": {
			source: `func into[M proto.Message](raw []byte, m M) error { return proto.Unmarshal(raw, m) }
var _ = into[*basev0.WorkContextV1]`,
			says: "interface or a type parameter",
		},
		// R2: interface embedding. Resolved to "r6msg".
		"an embedded interface": {
			source: `type carrier interface{ proto.Message }
func into(raw []byte, m carrier) error { return proto.Unmarshal(raw, m) }`,
			says: "interface or a type parameter",
		},
		// R3: an alias of proto.Message. Only aliases of CORE's types were
		// refused, and proto.Message is not one.
		"an alias of the codec's own interface": {
			source: `type carrier = proto.Message
func into(raw []byte, m carrier) error { return proto.Unmarshal(raw, m) }`,
			says: "interface or a type parameter",
		},
		// R4: reflect. Resolved to "[]reflect#Value".
		"a codec reached through reflect": {
			source: `func into(raw []byte, c *basev0.WorkContextV1) {
	reflect.ValueOf(proto.Unmarshal).Call([]reflect.Value{reflect.ValueOf(raw), reflect.ValueOf(c)})
}`,
			says: "without calling it",
		},
		// L6: a closure. codecArguments read the OUTER call's arguments.
		"a codec handed to a closure": {
			source: `func use(f func([]byte, proto.Message) error) func([]byte, proto.Message) error { return f }
func into(raw []byte, c *basev0.WorkContextV1) error { return use(proto.Unmarshal)(raw, c) }`,
			says: "without calling it",
		},
		// The concrete capability, named outright, outside its one row.
		"the capability named outright": {
			source: `func into(raw []byte) (*basev0.WorkContextV1, error) {
	c := &basev0.WorkContextV1{}
	return c, proto.Unmarshal(raw, c)
}`,
			says: "which is or contains",
		},
		// L5's other half: the capability reached THROUGH A FIELD, by an alias
		// declared in another file. No syntactic rule could resolve it.
		// ROUND EIGHT'S BLOCKER, and the lesson is that round seven's fix
		// closed a SUBCLASS. A concrete FUNCTION type implementing
		// proto.Message by delegation: no interface in the signature, no
		// capability type anywhere, and the promoted method reaches the
		// capability. Executed against the previous head on a real
		// core-minted token.
		"a concrete func type implementing proto.Message": {
			source: `type thunk func() protoreflect.Message

func (f thunk) ProtoReflect() protoreflect.Message { return f() }

func decode(raw []byte, claims *basev0.WorkContextV1) error {
	return proto.Unmarshal(raw, thunk(claims.ProtoReflect))
}`,
			says: "hand-writes ProtoReflect",
		},
		// The same, lazily, through a struct whose FIELD is a func —
		// carriesAnInterface finds no interface in a func-typed field.
		"a struct with a func field": {
			source: `type lazy struct{ get func() protoreflect.Message }

func (l lazy) ProtoReflect() protoreflect.Message { return l.get() }

func decode(raw []byte, claims *basev0.WorkContextV1) error {
	return proto.Unmarshal(raw, lazy{get: claims.ProtoReflect})
}`,
			says: "hand-writes ProtoReflect",
		},
		// And the v1 contract, which proto.Unmarshal still accepts through
		// protoimpl — so the rule covers both or it covers one spelling.
		"the v1 message contract": {
			source: `type legacy struct{ inner *basev0.WorkContextV1 }

func (legacy) Reset()         {}
func (legacy) String() string { return "" }
func (legacy) ProtoMessage()  {}`,
			says: "hand-writes ProtoMessage",
		},
		// ROUND SEVEN'S BLOCKER: a CONCRETE wrapper around an embedded
		// interface. No handwritten anything — the promoted ProtoReflect
		// delegates to the capability, so this is the ordinary protobuf
		// decoder, and three separate checks each missed it for a different
		// reason.
		"a concrete wrapper around an embedded codec interface": {
			source: `type envelopeTarget struct{ proto.Message }

func decode(raw []byte, dst *basev0.WorkContextV1) error {
	return proto.Unmarshal(raw, &envelopeTarget{Message: dst})
}`,
			says: "interface or a type parameter",
		},
		// And the same hiding place one level deeper, so the walk is
		// transitive rather than one-field-deep.
		"an interface two structs down": {
			source: `type inner struct{ proto.Message }
type outer struct {
	Name  string
	Inner inner
}

func decode(raw []byte, dst *basev0.WorkContextV1) error {
	wrapped := outer{Inner: inner{Message: dst}}
	return proto.Unmarshal(raw, &wrapped.Inner)
}`,
			says: "interface or a type parameter",
		},
		// A SLICE of them, because a codec takes one element at a time and the
		// walk must not stop at the container.
		"an interface behind a slice": {
			source: `type batch []proto.Message

func decode(raw []byte, all batch) error { return proto.Unmarshal(raw, all[0]) }`,
			says: "interface or a type parameter",
		},
		// L5, as executed: json.Marshal of a struct whose EMBEDDED field is a
		// capability, through an alias declared in another file. The argument's
		// own type is concrete — mintRequest — so no interface rule fires and
		// no type-name rule could resolve the alias across files. The walk
		// finds it inside the struct.
		"a capability embedded in a permitted struct": {
			source: `type claims = basev0.WorkContextV1
type mintRequest struct {
	Audience string
	*claims
}
func out(audience string, c *claims) ([]byte, error) {
	return json.Marshal(mintRequest{Audience: audience, claims: c})
}`,
			says: "which is or contains",
		},
	} {
		t.Run(name, func(t *testing.T) {
			loaded, file := typeCheckedProbe(t, preamble+probe.source)
			findings := inspectCodecUses(loaded, file, "second_implementation.go")
			require.NotEmpty(t, findings, "the gate accepted a shape that decodes a capability")
			require.Contains(t, strings.Join(findings, "\n"), probe.says)
		})
	}

	// R8: a SECOND method named Handle, on a new type, IN THE RECEIPTS PACKAGE
	// — so the package key passes and the receiver key is what has to refuse
	// it. The allowlist was keyed on the function's name, and a reviewer wrote
	// this and was permitted.
	const receiptsPath = "github.com/codefly-dev/sdk-go/receipts"
	t.Run("a second method spelled like an allowlisted one", func(t *testing.T) {
		loaded, file := typeCheckedProbeIn(t, receiptsPath, preamble+`type other struct{}

func (other) Handle(raw []byte, m proto.Message) error { return proto.Unmarshal(raw, m) }`)
		require.NotEmpty(t, inspectCodecUses(loaded, file, "receipts/interceptor.go"),
			"the allowlist named Interceptor.Handle, not every method spelled Handle")
	})

	// And the method the row was actually written for, in the same package, is
	// permitted — which is what makes the case above about the RECEIVER and
	// not about the package.
	t.Run("the method the row was written for", func(t *testing.T) {
		loaded, file := typeCheckedProbeIn(t, receiptsPath, preamble+`type Interceptor struct{}

func (*Interceptor) Handle(raw []byte, m proto.Message) error { return proto.Unmarshal(raw, m) }`)
		require.Empty(t, inspectCodecUses(loaded, file, "receipts/interceptor.go"),
			"receipts.Interceptor.Handle takes a proto.Message by design")
	})

	// THE KEY ITSELF, because the decision alone was satisfied either way by
	// two coupled edits.
	t.Run("the allowlist key carries the receiver", func(t *testing.T) {
		for name, probe := range map[string]struct{ source, key string }{
			"a method on the type the row names": {
				source: `type Interceptor struct{}

func (*Interceptor) Handle(raw []byte, m proto.Message) error { return proto.Unmarshal(raw, m) }`,
				key: "Interceptor.Handle",
			},
			"the same method name on another type": {
				source: `type other struct{}

func (other) Handle(raw []byte, m proto.Message) error { return proto.Unmarshal(raw, m) }`,
				key: "other.Handle",
			},
			"a plain function": {
				source: `func RequestDigest(m proto.Message) ([]byte, error) { return proto.Marshal(m) }`,
				key:    "RequestDigest",
			},
		} {
			t.Run(name, func(t *testing.T) {
				loaded, file := typeCheckedProbeIn(t, receiptsPath, preamble+probe.source)
				var found string
				ast.Inspect(file, func(node ast.Node) bool {
					if call, ok := node.(*ast.CallExpr); ok && found == "" {
						if _, key := indirectionKeyAt(loaded, file, call.Pos()); key != "" {
							found = key
						}
					}
					return true
				})
				require.Equal(t, probe.key, found,
					"the allowlist is keyed on this string; a key without the receiver permits "+
						"every method spelled the same")
			})
		}
	})

	// CODEX 2: base64 DECODING through an ALIASED RECEIVER, in the one file
	// allowed to reach base64 at all. The syntactic rule required the receiver
	// to be written as `base64.RawURLEncoding`, so one assignment walked past
	// it — a spelling standing in for a kind, the same correction the codec
	// rule needed.
	t.Run("base64 decoding through an aliased receiver", func(t *testing.T) {
		loaded, file := typeCheckedProbe(t, `package probe

import "encoding/base64"

var payloadEncoding = base64.RawURLEncoding

func openPayload(s string) ([]byte, error) { return payloadEncoding.DecodeString(s) }
`)
		findings := inspectCodecUses(loaded, file, "workcontext/cache_partition.go")
		require.NotEmpty(t, findings, "the file that may ENCODE a cache key may never DECODE")
		require.Contains(t, strings.Join(findings, "\n"), "may never")
	})

	// And the shapes that file legitimately uses stay legitimate, which is the
	// mutation guard for the case above.
	t.Run("encoding a cache key is still permitted", func(t *testing.T) {
		loaded, file := typeCheckedProbe(t, `package probe

import "encoding/base64"

var payloadEncoding = base64.RawURLEncoding

func key(raw []byte) string { return payloadEncoding.EncodeToString(raw) }
`)
		require.Empty(t, inspectCodecUses(loaded, file, "workcontext/cache_partition.go"))
	})

	// A CAPABILITY HANDED INTO A PERMITTED INDIRECTION. The exemption is for
	// the codec call inside those four functions; their callers were never
	// looked at, and configuration_document.go json-decodes into its
	// destination with the generated struct's snake_case tags.
	t.Run("a capability passed into a permitted indirection", func(t *testing.T) {
		const rootPath = "github.com/codefly-dev/sdk-go"
		loaded, file := typeCheckedProbeIn(t, rootPath, preamble+`func decodeDocument(name string, content []byte, destination any) error {
	return json.Unmarshal(content, destination)
}

func read(raw []byte) (*basev0.WorkContextV1, error) {
	claims := &basev0.WorkContextV1{}
	return claims, decodeDocument("work-context", raw, claims)
}`)
		findings := inspectCodecUses(loaded, file, "configuration_document.go")
		require.NotEmpty(t, findings,
			"the exemption is for the codec INSIDE decodeDocument, not for handing it a capability")
		require.Contains(t, strings.Join(findings, "\n"), "into github.com/codefly-dev/sdk-go.decodeDocument")
	})

	// A POINTER TO AN INTERFACE is still an interface's worth of unknown, and
	// json.Marshal takes `any`, so it is a shape that compiles.
	t.Run("a pointer to an interface", func(t *testing.T) {
		loaded, file := typeCheckedProbe(t, preamble+`func out(m *proto.Message) ([]byte, error) { return json.Marshal(m) }`)
		require.NotEmpty(t, inspectCodecUses(loaded, file, "second_implementation.go"),
			"what the pointer points at is chosen by the caller, capability included")
	})

	// AND THE FOUR REAL INDIRECTIONS STAY PERMITTED, which is the mutation
	// guard for all of the above: a rule that refuses everything is not a rule.
	t.Run("the real indirections are still permitted", func(t *testing.T) {
		for _, module := range loadModules(t) {
			for _, loaded := range module.packages {
				if loaded.TypesInfo == nil {
					continue
				}
				for _, file := range loaded.Syntax {
					path := module.relative(loaded, file)
					if path == "" || strings.HasSuffix(path, "_test.go") {
						continue
					}
					require.Empty(t, inspectCodecUses(loaded, file, path),
						"%s is code this repository ships", path)
				}
			}
		}
	})
}

// The indirection count is CHECKED, not written in prose. "Three, all in
// receipts" sat above a list of four for two rounds — the C10 class, which this
// repository has now had five times — so the prose says "four" and this fails
// if it stops being four.
func TestTheIndirectionListIsAsSmallAsItClaims(t *testing.T) {
	var total int
	for _, names := range codecIndirectionObjects {
		total += len(names)
	}
	require.Equal(t, 4, total,
		"there are %d codec indirections now. Each one is a function allowed to apply a "+
			"codec to a value whose type nothing knows statically, so the list is the "+
			"gate's widest hole and its size belongs in a reviewed diff — update the "+
			"comment above codecIndirectionObjects and this number together.", total)
}
