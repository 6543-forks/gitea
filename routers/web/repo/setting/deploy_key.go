// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"errors"
	"net/http"

	asymkey_model "gitea.dev/models/asymkey"
	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	deploykey_model "gitea.dev/models/deploykey"
	"gitea.dev/models/perm"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/htmlutil"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/templates"
	"gitea.dev/modules/util"
	shared_user "gitea.dev/routers/web/shared/user"
	asymkey_service "gitea.dev/services/asymkey"
	"gitea.dev/services/audit"
	"gitea.dev/services/context"
	"gitea.dev/services/forms"
)

const tplOrgDeployKeys templates.TplName = "org/settings/deploy_keys"

// deployKeysCtx is where the deploy-keys of a settings page belong: a repository or an organization.
type deployKeysCtx struct {
	Owner        *user_model.User
	Repo         *repo_model.Repository
	Scope        deploykey_model.Scope
	Template     templates.TplName
	RedirectLink string
}

func getDeployKeysCtx(ctx *context.Context) *deployKeysCtx {
	if ctx.Data["PageIsOrgSettings"] == true {
		return &deployKeysCtx{
			Owner:        ctx.ContextUser,
			Scope:        deploykey_model.Scope{OwnerID: ctx.ContextUser.ID},
			Template:     tplOrgDeployKeys,
			RedirectLink: ctx.Org.OrgLink + "/settings/keys",
		}
	}
	return &deployKeysCtx{
		Repo:         ctx.Repo.Repository,
		Scope:        deploykey_model.Scope{RepoID: ctx.Repo.Repository.ID},
		Template:     tplDeployKeys,
		RedirectLink: ctx.Repo.RepoLink + "/settings/keys",
	}
}

func DeployKeys(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("repo.settings.deploy_keys")
	ctx.Data["PageIsSettingsKeys"] = true
	ctx.Data["DisableSSH"] = setting.SSH.Disabled

	dCtx := getDeployKeysCtx(ctx)
	if dCtx.Owner != nil {
		if _, err := shared_user.RenderUserOrgHeader(ctx); err != nil {
			ctx.ServerErrorAuto(err)
			return
		}
	}

	keys, err := db.Find[deploykey_model.DeployKey](ctx, deploykey_model.ListDeployKeysOptions{Scope: dCtx.Scope})
	if err != nil {
		ctx.ServerErrorAuto(err)
		return
	}
	ctx.Data["DeployKeys"] = keys
	ctx.HTML(http.StatusOK, dCtx.Template)
}

func DeployKeysPost(ctx *context.Context) {
	form := context.GetFetchActionForm[*forms.AddKeyForm](ctx)
	if form == nil {
		return
	}
	content, err := asymkey_model.CheckPublicKeyString(form.Content)
	if err != nil {
		if db.IsErrSSHDisabled(err) {
			ctx.JSONError(ctx.Tr("settings.ssh_disabled"))
		} else if asymkey_model.IsErrKeyUnableVerify(err) {
			ctx.JSONErrorWithField(ctx.Tr("form.unable_verify_ssh_key"), "content")
		} else if errors.Is(err, asymkey_model.ErrKeyIsPrivate) {
			ctx.JSONErrorWithField(ctx.Tr("form.must_use_public_key"), "content")
		} else {
			ctx.JSONErrorWithField(ctx.Tr("form.invalid_ssh_key", err.Error()), "content")
		}
		return
	}

	accessMode := util.Iif(form.IsWritable, perm.AccessModeWrite, perm.AccessModeRead)
	key, err := deploykey_model.AddDeployKeySSH(ctx, ctx.Repo.Repository.ID, form.Title, content, accessMode)
	if err != nil {
		switch {
		case deploykey_model.IsErrDeployKeyAlreadyExist(err):
			ctx.JSONErrorWithField(ctx.Tr("repo.settings.key_been_used"), "content")
		case asymkey_model.IsErrKeyAlreadyExist(err):
			ctx.JSONErrorWithField(ctx.Tr("settings.ssh_key_been_used"), "content")
		case asymkey_model.IsErrKeyNameAlreadyUsed(err), deploykey_model.IsErrDeployKeyNameAlreadyUsed(err):
			ctx.JSONErrorWithField(ctx.Tr("repo.settings.key_name_used"), "title")
		default:
			ctx.ServerErrorAuto(err)
		}
		return
	}

	audit.Record(ctx, audit_model.RepositoryDeployKeyAdd, ctx.Repo.Repository, "deploy_key", key.Name)
	ctx.Flash.Success(ctx.Tr("repo.settings.add_key_success", key.Name))
	ctx.JSONRedirect(ctx.Repo.RepoLink + "/settings/keys")
}

func DeleteDeployKey(ctx *context.Context) {
	dCtx := getDeployKeysCtx(ctx)
	key, err := asymkey_service.DeleteDeployKey(ctx, dCtx.Scope, ctx.FormInt64("id"))
	if err != nil && !deploykey_model.IsErrDeployKeyNotExist(err) { // a key that is already gone leaves the caller with the state it asked for
		ctx.ServerErrorAuto(err)
		return
	}
	if key != nil {
		ctx.Flash.Success(ctx.Tr("repo.settings.deploy_key_deletion_success", key.Name))
	}
	ctx.JSONRedirect(dCtx.RedirectLink)
}

func DeployKeyGenerateToken(ctx *context.Context) {
	form := context.GetFetchActionForm[*forms.AddDeployTokenForm](ctx)
	if form == nil {
		return
	}

	dCtx := getDeployKeysCtx(ctx)
	accessMode := util.Iif(form.IsWritable, perm.AccessModeWrite, perm.AccessModeRead)
	key, err := deploykey_model.AddDeployKeyToken(ctx, dCtx.Scope, form.Title, accessMode)
	if err != nil {
		if deploykey_model.IsErrDeployKeyNameAlreadyUsed(err) {
			ctx.JSONErrorWithField(ctx.Tr("repo.settings.key_name_used"), "title")
		} else {
			ctx.ServerErrorAuto(err)
		}
		return
	}
	audit.RecordScoped(ctx, dCtx.Owner, dCtx.Repo, audit.DeployKeyAdd, "deploy_key", key.Name)

	ctx.Flash.Success(ctx.Tr("repo.settings.generate_deploy_token_success", htmlutil.HTMLFormat("<code>%s</code>", key.Token)))
	ctx.JSONRedirect(dCtx.RedirectLink)
}

func DeployKeyRegenerateToken(ctx *context.Context) {
	dCtx := getDeployKeysCtx(ctx)
	key, err := deploykey_model.RegenerateDeployKeyToken(ctx, dCtx.Scope, ctx.FormInt64("id"))
	if err != nil {
		if deploykey_model.IsErrDeployKeyNotExist(err) {
			ctx.JSONErrorNotFound()
		} else {
			ctx.ServerErrorAuto(err)
		}
		return
	}
	audit.RecordScoped(ctx, dCtx.Owner, dCtx.Repo, audit.DeployKeyRegenerate, "deploy_key", key.Name)

	ctx.Flash.Success(ctx.Tr("repo.settings.regenerate_deploy_token_success", htmlutil.HTMLFormat("<code>%s</code>", key.Token)))
	ctx.JSONRedirect(dCtx.RedirectLink)
}
