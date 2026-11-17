// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	auth_model "gitea.dev/models/auth"
	deploykey_model "gitea.dev/models/deploykey"
	"gitea.dev/models/perm"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/git/gitcmd"
	lfs_module "gitea.dev/modules/lfs"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	"gitea.dev/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeployTokenGitHTTP(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		otherRepo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
		readKey, err := deploykey_model.AddDeployKeyToken(t.Context(), deploykey_model.Scope{RepoID: repo.ID}, "read", perm.AccessModeRead)
		require.NoError(t, err)
		writeKey, err := deploykey_model.AddDeployKeyToken(t.Context(), deploykey_model.Scope{RepoID: repo.ID}, "write", perm.AccessModeWrite)
		require.NoError(t, err)

		requestAs := func(t *testing.T, token, path string, expected int) {
			MakeRequest(t, NewRequest(t, "GET", path).AddBasicAuth("deploy-token", token), expected)
		}

		t.Run("Clone", func(t *testing.T) {
			requestAs(t, readKey.Token, "/"+repo.FullName()+"/info/refs?service=git-upload-pack", http.StatusOK)
		})
		t.Run("PushWithReadToken", func(t *testing.T) {
			pushURL := *u
			pushURL.Path = "/" + repo.FullName() + ".git"
			pushURL.User = url.UserPassword("deploy-token", readKey.Token)
			_, _, err := gitcmd.NewCommand("push").AddDynamicArguments(pushURL.String(), "HEAD:refs/heads/read-token-push").WithRepo(repo).RunStdString(t.Context())
			require.Error(t, err)
			assert.Contains(t, err.Stderr(), "User permission denied for writing.")
		})
		t.Run("PushWithWriteToken", func(t *testing.T) {
			requestAs(t, writeKey.Token, "/"+repo.FullName()+"/info/refs?service=git-receive-pack", http.StatusOK)
		})
		t.Run("OtherRepo", func(t *testing.T) {
			requestAs(t, readKey.Token, "/"+otherRepo.FullName()+"/info/refs?service=git-upload-pack", http.StatusNotFound)
		})
		t.Run("Organization", func(t *testing.T) {
			orgKey, err := deploykey_model.AddDeployKeyToken(t.Context(), deploykey_model.Scope{OwnerID: 3}, "org", perm.AccessModeRead)
			require.NoError(t, err)
			requestAs(t, orgKey.Token, "/org3/repo3/info/refs?service=git-upload-pack", http.StatusOK)
			requestAs(t, orgKey.Token, "/org3/repo5/info/refs?service=git-upload-pack", http.StatusOK)
			requestAs(t, orgKey.Token, "/"+otherRepo.FullName()+"/info/refs?service=git-upload-pack", http.StatusNotFound)
		})
		t.Run("UnknownToken", func(t *testing.T) {
			requestAs(t, deploykey_model.DeployTokenPrefix+"0123456789abcdef", "/"+repo.FullName()+"/info/refs?service=git-upload-pack", http.StatusUnauthorized)
		})
		t.Run("RejectedOutsideGitHTTP", func(t *testing.T) {
			// the owner of the repo would be able to read it, the token must not act as that owner
			requestAs(t, readKey.Token, "/api/v1/repos/"+repo.FullName(), http.StatusUnauthorized)
		})

		t.Run("LFS", func(t *testing.T) {
			defer test.MockVariableValue(&setting.LFS.StartServer, true)()

			batchAs := func(t *testing.T, token, repoName, operation string, expected int) {
				req := NewRequestWithJSON(t, "POST", "/"+repoName+"/info/lfs/objects/batch", lfs_module.BatchRequest{Operation: operation}).
					AddBasicAuth("deploy-token", token).
					SetHeader("Accept", lfs_module.AcceptHeader).
					SetHeader("Content-Type", lfs_module.MediaType)
				MakeRequest(t, req, expected)
			}

			batchAs(t, readKey.Token, repo.FullName(), "download", http.StatusOK)
			batchAs(t, readKey.Token, repo.FullName(), "upload", http.StatusUnauthorized)
			batchAs(t, writeKey.Token, repo.FullName(), "upload", http.StatusOK)
			batchAs(t, readKey.Token, otherRepo.FullName(), "download", http.StatusUnauthorized)
		})
	})
}

func TestDeployTokenOrgSettings(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	session := loginUser(t, "user2")

	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/settings/keys/generate-token", map[string]string{"title": "ci"}), http.StatusOK)
	key := unittest.AssertExistsAndLoadBean(t, &deploykey_model.DeployKey{OwnerID: 3, Name: "ci"})
	assert.True(t, key.IsReadOnly())

	resp := session.MakeRequest(t, NewRequest(t, "GET", "/org/org3/settings/keys"), http.StatusOK)
	assert.Equal(t, "ci", NewHTMLParser(t, resp.Body).Find(".item-title").Text())
	session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/settings/keys"), http.StatusOK)

	session.MakeRequest(t, NewRequestWithValues(t, "POST", fmt.Sprintf("/org/org3/settings/keys/delete?id=%d", key.ID), nil), http.StatusOK)
	unittest.AssertNotExistsBean(t, &deploykey_model.DeployKey{ID: key.ID})
}

func TestAPIOrgDeployToken(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization)

	req := NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/keys/tokens", api.CreateDeployKeyTokenOption{Title: "ci", ReadOnly: true}).AddTokenAuth(token)
	created := DecodeJSON(t, MakeRequest(t, req, http.StatusCreated), &api.DeployKey{})
	assert.True(t, created.ReadOnly)
	assert.NotEmpty(t, created.Token)
	unittest.AssertExistsAndLoadBean(t, &deploykey_model.DeployKey{ID: created.ID, OwnerID: 3})

	resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/keys").AddTokenAuth(token), http.StatusOK)
	keys := DecodeJSON(t, resp, []*api.DeployKey{})
	require.Len(t, keys, 1)
	assert.Empty(t, keys[0].Token, "the token is only shown when it is created")
	assert.Equal(t, "1", resp.Header().Get("X-Total-Count"))

	keyURL := fmt.Sprintf("/api/v1/orgs/org3/keys/%d", created.ID)
	MakeRequest(t, NewRequest(t, "GET", keyURL).AddTokenAuth(getUserToken(t, "user4", auth_model.AccessTokenScopeReadOrganization)), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "DELETE", keyURL).AddTokenAuth(token), http.StatusNoContent)
	MakeRequest(t, NewRequest(t, "GET", keyURL).AddTokenAuth(token), http.StatusNotFound)
}
