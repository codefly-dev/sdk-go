// Package enclosing decides whether the workspace on disk above a process is
// that process's composition. Every SDK reader that falls back to the
// workspace — endpoint selection and the native map, the local configuration
// and secret files, the fixture packages, the workspace name — asks here, so
// the SDK has one answer to the question rather than one per reader.
package enclosing

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/codefly-dev/core/resources"
)

// Injected is the composition the runtime started this process in, or "" when
// none did. Core's EnvironmentVariableManager.SetIdentity sets it for every
// agent-run service, so a process started by `codefly run` or `codefly test`
// carries it; a local tool, a plain `go test` or `go run` does not.
func Injected() string {
	return strings.TrimSpace(os.Getenv(resources.WorkspacePrefix))
}

// Unreadable is a workspace file above the process that could not be decoded,
// so it could not name itself and did not count. A caller that then finds
// nothing injected for it reports this too: when that file was the
// composition's own, the decode error is the diagnosis.
type Unreadable struct {
	Dir string
	Err error
}

// ErrHostResolution is this SDK's answer when core asks it to acquire a
// workspace that a composition imports by release: it acquires nothing. Core's
// WorkspaceResolver is the acquisition boundary a host supplies — the CLI
// fetches the release and registers one — and an SDK that resolved values by
// fetching repositories would be the CLI again. Core wraps the answer into its
// load failure, so a caller tells "only the host can compose this" from every
// other load failure with errors.Is, never by reading a message.
var ErrHostResolution = errors.New("this SDK acquires no released workspace; only the host resolves it")

func refuseAcquisition(_ context.Context, ref *resources.WorkspaceReference) (string, error) {
	return "", fmt.Errorf("%w: %s at %s@%s", ErrHostResolution, ref.Name, ref.Source, ref.Version)
}

// HostComposed is the composition's own workspace file above the process that
// only the host can compose: it imports a workspace by release, and this SDK
// acquires nothing. It is not taken as a loaded composition, so the carriers
// the composition injected answer, exactly as they do for a process with no
// workspace, and a caller reporting an absent carrier says this is why no
// declaration was judged here. Err is core's load failure, wrapping
// ErrHostResolution and naming the import.
type HostComposed struct {
	Dir string
	Err error
}

// Composition returns the workspace above the process when it is the
// composition the process runs in, loaded and composed, and nil when there is
// none or the one found is someone else's.
//
// With an injected composition, a workspace counts only if it declares exactly
// that name — compared as written, as the runtime wrote it. A composed module's
// own checkout, a released tag in the module cache and a solution's tag all
// ship their producer's workspace file, which the process finds first and which
// says nothing about the composition it runs in. Such a workspace is never
// loaded. A workspace file that cannot be decoded cannot claim the name
// either; it is returned as Unreadable rather than loaded, so the caller can
// still answer from what the composition injected, and say why the file did
// not count when nothing was.
//
// With nothing injected, no composition started the process, and the enclosing
// workspace is the only one there is: it is loaded as found, and a load failure
// — an undecodable file included — is returned.
//
// Loading composes the workspace's imports, and a workspace that imports
// another by release — a solution importing its platform — needs that import
// acquired, which only the host does: the CLI fetches the release and hands
// core a WorkspaceResolver. This SDK hands core one that refuses, so core's
// own loader says exactly when that acquisition is the only thing between the
// file and a composition; the file is then returned as HostComposed rather
// than loaded. The process is inside its composition, the composition injected
// the carriers for what it may reach, and those answer — as for a process with
// no workspace — while an import the query never needed refuses nothing. A
// declaration this SDK cannot compose is not judged here; the composition
// judged it when it injected the carrier.
func Composition(ctx context.Context) (*resources.Workspace, *Unreadable, *HostComposed, error) {
	dir, err := find(ctx)
	if err != nil || dir == "" {
		return nil, nil, nil, err
	}
	if injected := Injected(); injected != "" {
		name, decodeErr := declaredName(ctx, dir)
		if decodeErr != nil {
			return nil, &Unreadable{Dir: dir, Err: decodeErr}, nil, nil
		}
		if name != injected {
			return nil, nil, nil, nil
		}
	}
	workspace, err := resources.LoadWorkspaceFromDir(resources.WithWorkspaceResolver(ctx, refuseAcquisition), dir)
	if err != nil {
		if errors.Is(err, ErrHostResolution) {
			return nil, nil, &HostComposed{Dir: dir, Err: err}, nil
		}
		return nil, nil, nil, err
	}
	return workspace, nil, nil, nil
}

// Name is the composition's name: the injected one, else the name the
// enclosing workspace file declares. The file is decoded, not composed, so a
// workspace whose imports only the CLI can resolve still has a name. "" means
// neither exists.
func Name(ctx context.Context) (string, error) {
	if injected := Injected(); injected != "" {
		return injected, nil
	}
	dir, err := find(ctx)
	if err != nil || dir == "" {
		return "", err
	}
	name, err := declaredName(ctx, dir)
	if err != nil {
		return "", err
	}
	return name, nil
}

func find(ctx context.Context) (string, error) {
	dir, err := resources.FindUp[resources.Workspace](ctx)
	if err != nil || dir == nil {
		return "", err
	}
	return *dir, nil
}

// declaredName reads the name the workspace file declares, without composing
// it or validating anything else about it. A file that decodes with no name
// names nothing, which matches no injected composition.
func declaredName(ctx context.Context, dir string) (string, error) {
	declared, err := resources.LoadFromDir[resources.Workspace](ctx, dir)
	if err != nil {
		return "", err
	}
	if declared == nil {
		return "", nil
	}
	return strings.TrimSpace(declared.Name), nil
}
