package workload

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"
)

// IdentitySet reads an admission set from its file, per call, and fails closed.
//
// No caching and no last-good fallback, which is the opposite of how the leaf
// this workload presents is treated: a leaf that cannot be re-read keeps
// serving, because the old leaf is this workload's own identity and refusing it
// only turns away callers who should be let in. An admission set that cannot be
// re-read has no such safe direction — the set on disk may be narrower than the
// one in memory, and that is the case this reads per handshake for.
//
// unresolved is the refusal's own words: what the set decides and how it is
// provisioned, so an operator is sent to the right place.
func IdentitySet(path, unresolved string) func() ([]string, error) {
	return func() ([]string, error) {
		if path == "" {
			return nil, fmt.Errorf("%s", unresolved)
		}
		content, err := readAdmissionFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: reading %q: %w", unresolved, path, err)
		}
		identities, err := ParseIdentities(content)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", unresolved, path, err)
		}
		if len(identities) == 0 {
			return nil, fmt.Errorf("%s: %q names none", unresolved, path)
		}
		return identities, nil
	}
}

// Intersect is the identities both sets admit, for a destination two roles
// share. A dial to a shared address cannot be attributed to one of them, so the
// only identity this workload may present its credentials to there is one both
// sets admit; an empty intersection admits nobody.
func Intersect(first, second func() ([]string, error), addr string) func() ([]string, error) {
	return func() ([]string, error) {
		one, err := first()
		if err != nil {
			return nil, err
		}
		other, err := second()
		if err != nil {
			return nil, err
		}
		var both []string
		for _, identity := range one {
			if slices.Contains(other, identity) {
				both = append(both, identity)
			}
		}
		if len(both) == 0 {
			return nil, fmt.Errorf("no identity at %s is in both provisioned sets, so there is none this workload may present its credentials to there: a dial to a shared address cannot be attributed to one role, so only an identity both admit is safe",
				addr)
		}
		return both, nil
	}
}

// admissionFileLimit caps an admission file.
//
// A set read on every handshake, on every dial, and once a second per
// established connection in each direction is not a file to read without a
// bound: a 10MB one measured 9.5ms per read, which is a cost an operator can
// inflict by accident and an attacker who can write that path can inflict on
// purpose. A realistic set is a handful of SPIFFE IDs.
const admissionFileLimit = 64 << 10

// readAdmissionFile reads an admission set with a size bound.
func readAdmissionFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	content, err := io.ReadAll(io.LimitReader(file, admissionFileLimit+1))
	if err != nil {
		return "", err
	}
	if len(content) > admissionFileLimit {
		return "", fmt.Errorf("the file is larger than %d bytes, which is not a set of identities: this is read on every handshake, every dial, and once a second per established connection", admissionFileLimit)
	}
	return string(content), nil
}

// ParseIdentities is the admitted set a file names, and an error for a file
// this package will not guess at.
//
// Each entry must be a *complete* line, which is the part that matters and is
// not obvious. A reader that split on whatever it was handed admitted a file
// caught mid-write — the platform rewriting it without an atomic swap, an
// operator's `>` redirect — with its truncated entry as an identity of its own:
// ".../sa/gateway-internal" read as ".../sa/gateway" and let in a caller the
// set never named. A trailing newline is the only evidence a line is whole, so
// a final fragment is refused rather than taken.
//
// Each entry is then checked to be a SPIFFE ID, because that is what it is
// compared against and an entry that cannot match anything is a provisioning
// mistake to name at boot rather than carry silently.
func ParseIdentities(raw string) ([]string, error) {
	if strings.HasPrefix(raw, "\ufeff") {
		return nil, fmt.Errorf("the file begins with a byte-order mark, so its first entry can never match an identity")
	}
	if raw != "" && !strings.HasSuffix(raw, "\n") {
		return nil, fmt.Errorf("the file does not end in a newline, so its last line may be a fragment of one — a set caught mid-rewrite would otherwise admit a truncated identity as an identity of its own")
	}
	var identities []string
	for _, line := range strings.Split(raw, "\n") {
		if hash := strings.Index(line, "#"); hash >= 0 {
			line = line[:hash]
		}
		for _, entry := range strings.Split(line, ",") {
			trimmed := strings.TrimSpace(entry)
			if trimmed == "" {
				continue
			}
			// Shape, not canonicalisation. An entry is matched by exact
			// string equality against the peer's single URI SAN, so a
			// percent-encoded, IDN, ported, userinfo-bearing or trailing-dot
			// variant fails closed — it simply never matches anything. This
			// refuses entries that could never match *anything at all*.
			if err := usableIdentity(trimmed); err != nil {
				return nil, err
			}
			identities = append(identities, trimmed)
		}
	}
	return identities, nil
}

// usableIdentity refuses an entry that could never match a peer, so the refusal
// names the provisioning rather than appearing later as a caller nobody admits.
func usableIdentity(entry string) error {
	for _, r := range entry {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0xfeff {
			return fmt.Errorf("the entry %q contains a control character, so it can never match an identity a peer presents", entry)
		}
	}
	parsed, err := url.Parse(entry)
	if err != nil {
		return fmt.Errorf("the entry %q is not a URI: an admitted identity is a SPIFFE ID, compared against the one URI SAN a peer's certificate carries", entry)
	}
	if parsed.Scheme != "spiffe" || parsed.Host == "" || parsed.Path == "" {
		return fmt.Errorf("the entry %q is not a SPIFFE ID (spiffe://<trust-domain>/<path>): it is compared against the one URI SAN a peer's certificate carries, so an entry of another shape admits nobody and is a provisioning mistake rather than a narrower set", entry)
	}
	return nil
}
