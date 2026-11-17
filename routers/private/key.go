// Copyright 2018 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package private

import (
	"errors"
	"net/http"

	asymkey_model "gitea.dev/models/asymkey"
	deploykey_model "gitea.dev/models/deploykey"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/modules/util"
	"gitea.dev/services/context"
)

// UpdatePublicKeyInRepo update public key and deploy key updates
func UpdatePublicKeyInRepo(ctx *context.PrivateContext) {
	keyID := ctx.PathParamInt64("id")
	repoID := ctx.PathParamInt64("repoid")
	if err := asymkey_model.UpdatePublicKeyUpdated(ctx, keyID); err != nil {
		ctx.PrivateInternalErrorf("%v", err)
		return
	}

	var deployKey *deploykey_model.DeployKey
	repo, err := repo_model.GetRepositoryByID(ctx, repoID)
	if err == nil {
		deployKey, err = deploykey_model.GetDeployKeyByRepoPublicKey(ctx, repo.ID, repo.OwnerID, keyID)
	}
	if err != nil {
		if errors.Is(err, util.ErrNotExist) {
			ctx.PlainText(http.StatusOK, "success")
			return
		}
		ctx.PrivateInternalErrorf("%v", err)
		return
	}
	if err = deploykey_model.UpdateDeployKeyLastUsed(ctx, deployKey.ID); err != nil {
		ctx.PrivateInternalErrorf("%v", err)
		return
	}

	ctx.PlainText(http.StatusOK, "success")
}

func AuthorizedPublicKeyForSSH(ctx *context.PrivateContext) {
	content := ctx.FormString("content")
	publicKey, err := asymkey_model.SearchPublicKeyForSSH(ctx, content)
	if err != nil {
		ctx.PrivateInternalErrorf("%v", err)
		return
	}

	authorizedString, err := asymkey_model.AuthorizedStringForKey(publicKey)
	if err != nil {
		ctx.PrivateInternalErrorf("%v", err)
		return
	}
	ctx.PlainText(http.StatusOK, authorizedString)
}
