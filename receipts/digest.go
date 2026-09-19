package receipts

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// RequestDigestFormatV1 is mixed into the digest so a change in how a request
// is fingerprinted changes every digest instead of colliding with the previous
// format.
const RequestDigestFormatV1 = "codefly.effect-receipt.request.digest/v1"

// RequestDigest fingerprints the request an effect is attempted for.
//
// The digest is taken over the proto3 JSON mapping with object keys sorted and
// whitespace removed, the canonical form core takes a package digest over. The
// protobuf wire encoding, even with Deterministic set, is only stable within
// one binary — and the two sides of this comparison are, by construction, not
// one binary: a receipt written before a deployment is compared against a
// request marshalled after it, which is the moment a wire-encoding digest would
// start reporting every recovered attempt as a reused effect id.
func RequestDigest(request proto.Message) ([]byte, error) {
	if request == nil {
		return nil, fmt.Errorf("%w: request is required", ErrInvalid)
	}
	encoded, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%w: encode canonical form: %v", ErrInvalid, err)
	}
	var generic any
	if decodeErr := json.Unmarshal(encoded, &generic); decodeErr != nil {
		return nil, fmt.Errorf("%w: decode canonical form: %v", ErrInvalid, decodeErr)
	}
	canonical, err := json.Marshal(generic)
	if err != nil {
		return nil, fmt.Errorf("%w: encode canonical form: %v", ErrInvalid, err)
	}
	digest := sha256.New()
	digest.Write([]byte(RequestDigestFormatV1))
	digest.Write([]byte{0})
	digest.Write(canonical)
	return digest.Sum(nil), nil
}
