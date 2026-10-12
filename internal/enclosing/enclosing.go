// Package enclosing decides whether the workspace on disk above a process is
// that process's composition. Every SDK reader that falls back to the
// workspace — endpoint selection and the native map, the local configuration
// and secret files, the fixture packages, the workspace name — asks here, so
// the SDK has one answer to the question rather than one per reader.
package enclosing

import (
	"context"
	"os"
	"strings"

	"github.com/codefly-dev/core/resources"
)

// Injected is the composition the runtime started this process in, or "" when
// none did. Core's EnvironmentVariableManager.SetIdentity sets it for every
// agent-run service, so a process started by `codefly run` always carries it;
// a local tool, a test or `go run` does not.
func Injected() string {
	return strings.TrimSpace(os.Getenv(resources.WorkspacePrefix))
}

// Composition returns the workspace above the process when it is the
// composition the process runs in, loaded and composed, and nil when there is
// none or the one found is someone else's.
//
// With an injected composition, a workspace counts only if it declares that
// name. A composed module's own checkout, a released tag in the module cache
// and a solution's tag all ship their producer's workspace file, which the
// process finds first and which says nothing about the composition it runs in.
// Such a workspace is never loaded: loading composes its imports, and a
// solution's tag imports its platform by release, which this SDK cannot
// resolve ("requires host resolution"). A workspace file that cannot be
// decoded cannot claim the name either. The caller then answers from what the
// composition injected, as it does for a process with no workspace at all.
//
// With nothing injected, no composition started the process, and the enclosing
// workspace is the only one there is: it is loaded as found, and a load failure
// is returned.
func Composition(ctx context.Context) (*resources.Workspace, error) {
	dir, err := find(ctx)
	if err != nil || dir == "" {
		return nil, err
	}
	if injected := Injected(); injected != "" {
		if name, ok := declaredName(ctx, dir); !ok || name != injected {
			return nil, nil
		}
	}
	return resources.LoadWorkspaceFromDir(ctx, dir)
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
	name, _ := declaredName(ctx, dir)
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
// it or validating anything else about it.
func declaredName(ctx context.Context, dir string) (string, bool) {
	declared, err := resources.LoadFromDir[resources.Workspace](ctx, dir)
	if err != nil || declared == nil {
		return "", false
	}
	name := strings.TrimSpace(declared.Name)
	return name, name != ""
}
