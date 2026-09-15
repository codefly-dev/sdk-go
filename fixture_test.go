package codefly_test

import (
	"path/filepath"
	"testing"

	"github.com/codefly-dev/core/composition"
	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const devAdminPackage = `kind: module-package
schema: codefly/module-package/v2
id: codefly/saas-starter
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
		"name: solution\nlayout: modules\nmodules:\n  - name: saas-starter\n  - name: plain\n")
	writeFile(t, filepath.Join(root, "modules", "saas-starter", composition.PackageManifestFileName), devAdminPackage)
	writeFile(t, filepath.Join(root, "modules", "saas-starter", "services", ".keep"), "")
	writeFile(t, filepath.Join(root, "modules", "plain", "services", ".keep"), "")
	t.Chdir(root)
}

func TestFixturePrincipalResolvesByRole(t *testing.T) {
	composingWorkspace(t)
	t.Setenv(resources.FixturePrefix, "dev-admin")

	principal, err := codefly.Fixture().Principal(t.Context(), "super_admin")

	require.NoError(t, err)
	assert.Equal(t, "dev-admin", principal.ID)
	assert.Equal(t, "admin@dev.local", principal.Email)
	assert.Equal(t, "dev-admin-provider-id", principal.Token)
}

func TestFixturePrincipalUnknownRoleNamesSeededRoles(t *testing.T) {
	composingWorkspace(t)
	t.Setenv(resources.FixturePrefix, "dev-admin")

	_, err := codefly.Fixture().Principal(t.Context(), "owner")

	require.ErrorIs(t, err, composition.ErrUnknownPrincipal)
	assert.Contains(t, err.Error(), "super_admin, member")
}

func TestFixturePrincipalUnknownFixtureNamesAvailableFixtures(t *testing.T) {
	composingWorkspace(t)
	t.Setenv(resources.FixturePrefix, "typo")

	_, err := codefly.Fixture().Principal(t.Context(), "super_admin")

	require.ErrorIs(t, err, composition.ErrUnknownFixture)
	assert.Contains(t, err.Error(), "dev-admin")
}

func TestFixturePrincipalWithoutSelectedFixture(t *testing.T) {
	composingWorkspace(t)
	t.Setenv(resources.FixturePrefix, "")

	_, err := codefly.Fixture().Principal(t.Context(), "super_admin")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no fixture is selected")
}

func TestFixturePrincipalResolvesWhenOneDirectoryIsReferencedTwice(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "workspace.codefly.yaml"),
		"name: solution\nlayout: modules\nmodules:\n  - name: saas-starter\n  - name: alias\n    path: modules/saas-starter\n")
	writeFile(t, filepath.Join(root, "modules", "saas-starter", composition.PackageManifestFileName), devAdminPackage)
	writeFile(t, filepath.Join(root, "modules", "saas-starter", "services", ".keep"), "")
	t.Chdir(root)
	t.Setenv(resources.FixturePrefix, "dev-admin")

	principal, err := codefly.Fixture().Principal(t.Context(), "super_admin")

	require.NoError(t, err)
	assert.Equal(t, "dev-admin", principal.ID)
}

func TestFixturePrincipalNamesPinnedModulesItCannotRead(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "workspace.codefly.yaml"),
		"name: solution\nlayout: modules\nmodules:\n  - name: saas-starter\n    source: codefly-dev/module-saas-starter\n    version: 0.1.0\n")
	t.Chdir(root)
	t.Setenv(resources.FixturePrefix, "dev-admin")

	_, err := codefly.Fixture().Principal(t.Context(), "super_admin")

	require.ErrorIs(t, err, composition.ErrUnknownFixture)
	assert.Contains(t, err.Error(), "saas-starter")
}
