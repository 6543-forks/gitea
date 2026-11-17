// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package deploykey

import (
	"testing"

	"gitea.dev/models/db"
	"gitea.dev/models/perm"
	"gitea.dev/models/unittest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeployToken(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	key, err := AddDeployKeyToken(t.Context(), Scope{RepoID: 1}, "ci", perm.AccessModeWrite)
	require.NoError(t, err)
	assert.False(t, key.IsReadOnly())
	assert.Len(t, key.Token, len(DeployTokenPrefix)+deployTokenLength)

	got, err := VerifyDeployKeyToken(t.Context(), key.Token)
	require.NoError(t, err)
	assert.Equal(t, key.ID, got.ID)
	assert.Empty(t, got.Token, "the token itself is never stored")

	_, err = VerifyDeployKeyToken(t.Context(), "not-a-token")
	assert.True(t, IsErrDeployKeyNotExist(err))

	_, err = AddDeployKeyToken(t.Context(), Scope{RepoID: 1}, "ci", perm.AccessModeWrite)
	assert.True(t, IsErrDeployKeyNameAlreadyUsed(err))

	regenerated, err := RegenerateDeployKeyToken(t.Context(), Scope{RepoID: 1}, key.ID)
	require.NoError(t, err)
	assert.Equal(t, key.Name, regenerated.Name)
	assert.Equal(t, key.Mode, regenerated.Mode)
	assert.False(t, unittest.AssertExistsAndLoadBean(t, &DeployKey{ID: key.ID}).HasUsed(), "regenerating is not a use")

	_, err = VerifyDeployKeyToken(t.Context(), key.Token)
	assert.True(t, IsErrDeployKeyNotExist(err), "the old token stops working")
	_, err = VerifyDeployKeyToken(t.Context(), regenerated.Token)
	require.NoError(t, err)

	// an SSH deploy-key has no token to regenerate
	sshKey := &DeployKey{RepoID: 1, KeyType: KeyTypeSSH, Name: "ssh"}
	require.NoError(t, db.Insert(t.Context(), sshKey))
	_, err = RegenerateDeployKeyToken(t.Context(), Scope{RepoID: 1}, sshKey.ID)
	assert.True(t, IsErrDeployKeyNotExist(err))
}

func TestDeployTokenOfOwner(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	orgKey, err := AddDeployKeyToken(t.Context(), Scope{OwnerID: 3}, "ci", perm.AccessModeRead)
	require.NoError(t, err)
	repoKey, err := AddDeployKeyToken(t.Context(), Scope{RepoID: 3}, "ci", perm.AccessModeRead)
	require.NoError(t, err, "a name is only unique within its scope")

	_, err = GetDeployKeyForRepo(t.Context(), 5, 3, orgKey.ID)
	require.NoError(t, err, "an organization key reaches every repository of the organization")
	_, err = GetDeployKeyForRepo(t.Context(), 1, 2, orgKey.ID)
	assert.True(t, IsErrDeployKeyNotExist(err))
	_, err = GetDeployKeyForRepo(t.Context(), 5, 3, repoKey.ID)
	assert.True(t, IsErrDeployKeyNotExist(err), "a repository key only reaches its own repository")

	keys, err := db.Find[DeployKey](t.Context(), ListDeployKeysOptions{Scope: Scope{OwnerID: 3}})
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, orgKey.ID, keys[0].ID)
}
