// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package org

import (
	"net/http"
	"net/url"

	asymkey_model "gitea.dev/models/asymkey"
	"gitea.dev/models/db"
	deploykey_model "gitea.dev/models/deploykey"
	"gitea.dev/models/perm"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/util"
	"gitea.dev/modules/web"
	"gitea.dev/routers/api/v1/repo"
	"gitea.dev/routers/api/v1/utils"
	asymkey_service "gitea.dev/services/asymkey"
	"gitea.dev/services/audit"
	"gitea.dev/services/context"
	"gitea.dev/services/convert"
)

func orgDeployKeyScope(ctx *context.APIContext) deploykey_model.Scope {
	return deploykey_model.Scope{OwnerID: ctx.Org.Organization.ID}
}

func orgAPIURL(ctx *context.APIContext) string {
	return setting.AppURL + "api/v1/orgs/" + url.PathEscape(ctx.Org.Organization.Name)
}

// ListDeployKeys lists the deploy keys of an organization
func ListDeployKeys(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/keys organization orgListDeployKeys
	// ---
	// summary: List an organization's deploy keys, they reach every repository of the organization
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: page
	//   in: query
	//   description: page number of results to return (1-based)
	//   type: integer
	// - name: limit
	//   in: query
	//   description: page size of results
	//   type: integer
	// responses:
	//   "200":
	//     "$ref": "#/responses/DeployKeyList"
	//   default:
	//     "$ref": "#/responses/error"

	keys, count, err := db.FindAndCount[deploykey_model.DeployKey](ctx, deploykey_model.ListDeployKeysOptions{
		ListOptions: utils.GetListOptions(ctx),
		Scope:       orgDeployKeyScope(ctx),
	})
	if err != nil {
		ctx.APIErrorInternal(err)
		return
	}

	apiKeys := make([]*api.DeployKey, len(keys))
	for i, key := range keys {
		apiKeys[i] = convert.ToDeployKey(ctx, orgAPIURL(ctx), key)
	}
	ctx.SetTotalCountHeader(count)
	ctx.JSON(http.StatusOK, &apiKeys)
}

// GetDeployKey gets a deploy key of an organization
func GetDeployKey(ctx *context.APIContext) {
	// swagger:operation GET /orgs/{org}/keys/{id} organization orgGetDeployKey
	// ---
	// summary: Get an organization's deploy key by id
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the key to get
	//   type: integer
	//   format: int64
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/DeployKey"
	//   default:
	//     "$ref": "#/responses/error"

	key, err := deploykey_model.GetDeployKeyByID(ctx, orgDeployKeyScope(ctx), ctx.PathParamInt64("id"))
	if err != nil {
		ctx.APIErrorAuto(err)
		return
	}
	ctx.JSON(http.StatusOK, convert.ToDeployKey(ctx, orgAPIURL(ctx), key))
}

// CreateDeployKey adds an SSH deploy key to an organization
func CreateDeployKey(ctx *context.APIContext) {
	// swagger:operation POST /orgs/{org}/keys organization orgCreateDeployKey
	// ---
	// summary: Add an SSH deploy key to an organization, it reaches every repository of the organization
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/CreateKeyOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/DeployKey"
	//   default:
	//     "$ref": "#/responses/error"

	form := web.GetForm[*api.CreateKeyOption](ctx)
	content, err := asymkey_model.CheckPublicKeyString(form.Key)
	if err != nil {
		repo.HandleCheckKeyStringError(ctx, err)
		return
	}

	accessMode := util.Iif(form.ReadOnly, perm.AccessModeRead, perm.AccessModeWrite)
	key, err := deploykey_model.AddDeployKeySSH(ctx, orgDeployKeyScope(ctx), form.Title, content, accessMode)
	if err != nil {
		repo.HandleAddKeyError(ctx, err)
		return
	}
	audit.RecordScoped(ctx, ctx.Org.Organization.AsUser(), nil, audit.DeployKeyAdd, "deploy_key", key.Name)
	ctx.JSON(http.StatusCreated, convert.ToDeployKey(ctx, orgAPIURL(ctx), key))
}

// CreateDeployToken creates a deploy token for an organization
func CreateDeployToken(ctx *context.APIContext) {
	// swagger:operation POST /orgs/{org}/keys/tokens organization orgCreateDeployToken
	// ---
	// summary: Add a deploy token to an organization, it authenticates git over HTTPS for every repository of the organization
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/CreateDeployKeyTokenOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/DeployKey"
	//   default:
	//     "$ref": "#/responses/error"

	form := web.GetForm[*api.CreateDeployKeyTokenOption](ctx)
	accessMode := util.Iif(form.ReadOnly, perm.AccessModeRead, perm.AccessModeWrite)
	key, err := deploykey_model.AddDeployKeyToken(ctx, orgDeployKeyScope(ctx), form.Title, accessMode)
	if err != nil {
		repo.HandleAddKeyError(ctx, err)
		return
	}
	audit.RecordScoped(ctx, ctx.Org.Organization.AsUser(), nil, audit.DeployKeyAdd, "deploy_key", key.Name)
	ctx.JSON(http.StatusCreated, convert.ToDeployKey(ctx, orgAPIURL(ctx), key))
}

// DeleteDeployKey deletes a deploy key of an organization
func DeleteDeployKey(ctx *context.APIContext) {
	// swagger:operation DELETE /orgs/{org}/keys/{id} organization orgDeleteDeployKey
	// ---
	// summary: Delete a deploy key from an organization
	// parameters:
	// - name: org
	//   in: path
	//   description: name of the organization
	//   type: string
	//   required: true
	// - name: id
	//   in: path
	//   description: id of the key to delete
	//   type: integer
	//   format: int64
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   default:
	//     "$ref": "#/responses/error"

	// a key that is already gone still leaves the caller with the state it asked for
	if _, err := asymkey_service.DeleteDeployKey(ctx, orgDeployKeyScope(ctx), ctx.PathParamInt64("id")); err != nil && !deploykey_model.IsErrDeployKeyNotExist(err) {
		ctx.APIErrorInternal(err)
		return
	}
	ctx.Status(http.StatusNoContent)
}
