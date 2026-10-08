// Package fixture resolves the fixture the Codefly runtime selected against the
// manifests of the packages the workspace composes.
//
// It lives OUT of sdk-go's root package deliberately. It is the only thing in
// the root that needed core/composition, and composition carries a GitHub
// release resolver — so every service that imported `codefly` for its own
// address linked a GitHub API client and an HTTP artifact downloader it never
// calls. Resolving a seeded identity by role is a TEST-time concern; a service
// binary has no business carrying the code that downloads release artifacts.
package fixture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/codefly-dev/core/composition"
	"github.com/codefly-dev/core/resources"
)

// Selection is the fixture the Codefly runtime selected for this
// process. It resolves against the manifests of the packages the workspace
// composes, so a test authenticates as a seeded identity by role instead of
// hardcoding one.
type Selection string

// Principal returns the identity the selected fixture seeds for role. Resolving
// by role means a renamed or dropped principal fails here, against the package
// version the solution composed, rather than at login.
//
// Only modules that resolve to a local directory are read. A pinned module
// lives in an artifact the Codefly CLI materializes, so a fixture it declares
// is invisible here: an unresolved name reports those modules, and a name that
// a local module also declares resolves to the local one without reporting the
// ambiguity.
func (fixture Selection) Principal(ctx context.Context, role string) (*composition.FixturePrincipal, error) {
	name := strings.TrimSpace(string(fixture))
	if name == "" {
		return nil, errors.New("resolve fixture principal: no fixture is selected")
	}
	manifests, pinned, err := composedPackages(ctx)
	if err != nil {
		return nil, err
	}
	resolved, err := composition.ResolveFixture(name, manifests...)
	if err != nil {
		// A pinned module lives in an artifact the CLI materializes, so its
		// fixtures are absent from what we could read. Saying only that the name
		// is unknown would point at the fixture rather than at the package the
		// SDK never saw.
		if len(pinned) > 0 && errors.Is(err, composition.ErrUnknownFixture) {
			return nil, fmt.Errorf("%w; pinned modules (%s) are materialized by the Codefly CLI and were not read", err, strings.Join(pinned, ", "))
		}
		return nil, err
	}
	return resolved.Principal(role)
}

// composedPackages loads the package manifest of every module the enclosing
// workspace composes, and names the pinned ones it cannot reach. A module that
// ships no package manifest is not packageable and declares no fixtures.
func composedPackages(ctx context.Context) ([]*composition.PackageManifest, []string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	workspace, err := resources.FindWorkspaceUp(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve Codefly workspace: %w", err)
	}
	if workspace == nil {
		return nil, nil, errors.New("resolve Codefly workspace: no enclosing workspace")
	}
	resolutions, err := workspace.ResolveModules(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve composed modules: %w", err)
	}
	var manifests []*composition.PackageManifest
	var pinned []string
	loaded := make(map[string]bool, len(resolutions))
	for _, resolution := range resolutions {
		if resolution.Dir == "" {
			pinned = append(pinned, resolution.Module)
			continue
		}
		// Two references can name one directory: a module listed twice, or an
		// alias carrying a path override. Loading it once per reference would
		// present a single package to the resolver as two, which comes back as
		// that package colliding with itself.
		directory := filepath.Clean(resolution.Dir)
		if loaded[directory] {
			continue
		}
		loaded[directory] = true
		manifest, err := composition.LoadPackageManifest(resolution.Dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("load module %s package manifest: %w", resolution.Module, err)
		}
		manifests = append(manifests, manifest)
	}
	return manifests, pinned, nil
}

// Selected is the fixture the Codefly runtime chose for this process. Product
// code must not depend on the runtime's environment-variable representation.
func Selected() Selection {
	return Selection(os.Getenv(resources.FixturePrefix))
}

// With reports whether the selected fixture matches name.
func With(name string) bool {
	return resources.Match(string(Selected()), name)
}
