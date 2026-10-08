package fixture_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/codefly-dev/core/composition"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/sdk-go/fixture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const devAdminPackage = `kind: module-package
schema: codefly/module-package/v2
id: example/starter
version: 0.1.0
minimum-codefly-version: ">=0.3.32"
artifact-roots:
  - services
contracts:
  composition: ">=2.0 <3.0"
  fixtures: ">=1.0 <2.0"
fixtures:
  - name: dev-admin
    description: Seeded tenant with an administrator
    principals:
      - id: dev-admin
        email: admin@dev.local
        role: super_admin
        token: dev-admin-provider-id
      - id: dev-member
        email: member@dev.local
        role: member
        token: dev-member-provider-id
`

// composingWorkspace lays out a workspace that composes a module shipping the
// dev-admin fixture alongside one that ships no package manifest, and makes it
// the enclosing workspace for the test.
func composingWorkspace(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "workspace.codefly.yaml"),
		"name: solution\nlayout: modules\nmodules:\n  - name: starter\n  - name: plain\n")
	writeFile(t, filepath.Join(root, "modules", "starter", composition.PackageManifestFileName), devAdminPackage)
	writeFile(t, filepath.Join(root, "modules", "starter", "services", ".keep"), "")
	writeFile(t, filepath.Join(root, "modules", "plain", "services", ".keep"), "")
	t.Chdir(root)
}

func TestFixturePrincipalResolvesByRole(t *testing.T) {
	composingWorkspace(t)
	t.Setenv(resources.FixturePrefix, "dev-admin")

	principal, err := fixture.Selected().Principal(t.Context(), "super_admin")

	require.NoError(t, err)
	assert.Equal(t, "dev-admin", principal.ID)
	assert.Equal(t, "admin@dev.local", principal.Email)
	assert.Equal(t, "dev-admin-provider-id", principal.Token)
}

func TestFixturePrincipalUnknownRoleNamesSeededRoles(t *testing.T) {
	composingWorkspace(t)
	t.Setenv(resources.FixturePrefix, "dev-admin")

	_, err := fixture.Selected().Principal(t.Context(), "owner")

	require.ErrorIs(t, err, composition.ErrUnknownPrincipal)
	assert.Contains(t, err.Error(), "super_admin, member")
}

func TestFixturePrincipalUnknownFixtureNamesAvailableFixtures(t *testing.T) {
	composingWorkspace(t)
	t.Setenv(resources.FixturePrefix, "typo")

	_, err := fixture.Selected().Principal(t.Context(), "super_admin")

	require.ErrorIs(t, err, composition.ErrUnknownFixture)
	assert.Contains(t, err.Error(), "dev-admin")
}

func TestFixturePrincipalWithoutSelectedFixture(t *testing.T) {
	composingWorkspace(t)
	t.Setenv(resources.FixturePrefix, "")

	_, err := fixture.Selected().Principal(t.Context(), "super_admin")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no fixture is selected")
}

func TestFixturePrincipalResolvesWhenOneDirectoryIsReferencedTwice(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "workspace.codefly.yaml"),
		"name: solution\nlayout: modules\nmodules:\n  - name: starter\n  - name: alias\n    path: modules/starter\n")
	writeFile(t, filepath.Join(root, "modules", "starter", composition.PackageManifestFileName), devAdminPackage)
	writeFile(t, filepath.Join(root, "modules", "starter", "services", ".keep"), "")
	t.Chdir(root)
	t.Setenv(resources.FixturePrefix, "dev-admin")

	principal, err := fixture.Selected().Principal(t.Context(), "super_admin")

	require.NoError(t, err)
	assert.Equal(t, "dev-admin", principal.ID)
}

func TestFixturePrincipalNamesPinnedModulesItCannotRead(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "workspace.codefly.yaml"),
		"name: solution\nlayout: modules\nmodules:\n  - name: starter\n    source: example-org/module-starter\n    version: 0.1.0\n")
	t.Chdir(root)
	t.Setenv(resources.FixturePrefix, "dev-admin")

	_, err := fixture.Selected().Principal(t.Context(), "super_admin")

	require.ErrorIs(t, err, composition.ErrUnknownFixture)
	// The MODULE NAME and the fact that it is pinned, not merely some
	// substring of the error. Making this file generic shortened the expected
	// name to "starter", which is also a substring of the module's own source
	// "example-org/module-starter" — so the assertion stopped pinning WHICH
	// name the error has to carry, and would have passed on the source alone.
	// Generic fixtures were the point; a weaker assertion was not. The name
	// that was here before is deliberately not quoted: a cleanup that explains
	// itself by repeating what it removed has not removed it.
	assert.Contains(t, err.Error(), "starter",
		"the error must name the module whose fixtures could not be read")
	assert.Contains(t, err.Error(), "pinned",
		"and must say that it is PINNED, which is the diagnosis: an unknown-fixture "+
			"error here has meant a pinned module the SDK never read, not a wrong name")
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}
