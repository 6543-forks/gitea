// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v29

import (
	"context"

	"gitea.dev/modelmigration/base"

	"xorm.io/xorm"
)

func AddOwnerIDToDeployKey(_ context.Context, x base.EngineMigration) error {
	type DeployKey struct {
		OwnerID int64 `xorm:"NOT NULL DEFAULT 0 INDEX"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{
		IgnoreDropIndices: true,
		IgnoreConstrains:  true,
	}, new(DeployKey))
	return err
}
