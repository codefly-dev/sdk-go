// Command importsof prints every import path of the Go files named on stdin.
//
// IT EXISTS BECAUSE awk CANNOT PARSE GO, and five rounds of review proved it
// one shape at a time. The extractor it replaces was rewritten three times and
// each rewrite was walked past by source that compiles:
//
//	import (
//	        // )
//	        "crypto/ed25519"          // a ")" in a comment closed the block
//	)
//	import (`crypto/ed25519`; "fmt")  // a raw path before a quoted one
//	import                            // the keyword, then a newline,
//	        "crypto/ed25519"          // then the path
//	import /*
//	*/ "crypto/ed25519"               // a comment spanning lines
//	import "\x63rypto/ed25519"        // an escape sequence, and it compiles
//
// The last one is the argument in miniature: `"\x63rypto/ed25519"` IS
// "crypto/ed25519" to the Go compiler and is not the string `crypto/ed25519`
// to anything matching text. No regex over lines closes that; the language's
// own parser closes all five at once, because the question was always "what
// does Go think this file imports".
//
// This matters most where it is the ONLY gate. The AST gate reads the working
// tree; the ref sweep reads blobs out of `git cat-file` for every published
// ref, and it ran the shell extractor alone — so each shape above was a
// complete bypass of the required check for any branch.
//
// Input: one file path per line on stdin. Output: `path\timportpath` per
// import. A file that does not parse is a FAILURE, not a file with no imports:
// a sweep that reports success for what it could not read is the fail-open this
// repository has fixed four times.
package main

import (
	"bufio"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"strconv"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "importsof:", err)
		os.Exit(1)
	}
}

func run() error {
	fileSet := token.NewFileSet()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer func() {
		_ = out.Flush()
	}()
	for scanner.Scan() {
		path := scanner.Text()
		if path == "" {
			continue
		}
		// THE WHOLE FILE IS PARSED, not just its import block.
		//
		// It was ImportsOnly, on the reasoning that the sweep's subject is what
		// a file reaches for and a blob at some old ref need not build against
		// today's dependencies. The second half of that is still true and is
		// why this is a SYNTAX parse and not a type-check: resolving a file at a
		// two-year-old tag would need that tag's dependencies.
		//
		// The first half was wrong about what ImportsOnly does. It stops at the
		// first non-import declaration, so a file whose body does not parse
		// at all — an unfinished function, a missing expression — reads as a
		// file with imports and no problem, and the sweep's own documented
		// claim that "a file that does not parse is a failure, not a file with
		// no imports" was false for every one of them. It also stops reading at
		// the first declaration, so an import placed AFTER one is invisible:
		// a file whose first declaration is a var and whose import block follows
		// swept with no imports at all. Both are refused now.
		syntax, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		for _, imported := range syntax.Imports {
			// Unquote, so an escape sequence is the path Go sees rather than
			// the text somebody typed.
			spec, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return fmt.Errorf("%s: unquote %s: %w", path, imported.Path.Value, err)
			}
			if _, err := fmt.Fprintf(out, "%s\t%s\n", path, spec); err != nil {
				return fmt.Errorf("write: %w", err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read the file list: %w", err)
	}
	return nil
}
