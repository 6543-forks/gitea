// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package deploykey

import (
	"context"
	"time"

	"gitea.dev/models/asymkey"
	"gitea.dev/models/db"
	"gitea.dev/models/perm"
	"gitea.dev/modules/timeutil"

	"xorm.io/builder"
)

type KeyType int // SSH public key or HTTP auth token

const (
	KeyTypeSSH KeyType = iota + 1
	KeyTypeToken
)

type DeployKey struct {
	ID      int64 `xorm:"pk autoincr"`
	KeyID   int64 `xorm:"INDEX"`
	RepoID  int64 `xorm:"INDEX"`
	OwnerID int64 `xorm:"NOT NULL DEFAULT 0 INDEX"`
	Name    string

	KeyType KeyType `xorm:"NOT NULL DEFAULT 1"`

	Fingerprint string
	PublicKey   *asymkey.PublicKey `xorm:"-"`

	TokenHash string `xorm:"INDEX"` // sha256 of the token, which carries enough entropy to need no salt
	Token     string `xorm:"-"`     // only set when the token is created

	Mode perm.AccessMode `xorm:"NOT NULL DEFAULT 1"`

	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

// these methods below are mainly used by templates

func (key *DeployKey) HasRecentActivity() bool {
	return key.UpdatedUnix.AddDuration(7*24*time.Hour) > timeutil.TimeStampNow()
}

func (key *DeployKey) HasUsed() bool { return key.UpdatedUnix > key.CreatedUnix }

func (key *DeployKey) IsReadOnly() bool { return key.Mode == perm.AccessModeRead }

func (key *DeployKey) IsKeyTypeToken() bool { return key.KeyType == KeyTypeToken }

func init() {
	db.RegisterModel(new(DeployKey))
}

// Scope is what a deploy-key is added to, exactly one of its IDs is set.
type Scope struct {
	RepoID  int64
	OwnerID int64 // the key reaches every repository of this organization
}

func (s Scope) cond() builder.Cond {
	return builder.Eq{"repo_id": s.RepoID, "owner_id": s.OwnerID}
}

// reachRepoCond selects the deploy-keys that reach a repository: its own and those of its owner.
func reachRepoCond(repoID, ownerID int64) builder.Cond {
	return builder.Or(builder.Eq{"repo_id": repoID}, builder.Eq{"owner_id": ownerID})
}

func checkDeployKeyName(ctx context.Context, scope Scope, name string) error {
	has, err := db.Exist[DeployKey](ctx, scope.cond().And(builder.Eq{"name": name}))
	if err != nil {
		return err
	} else if has {
		return ErrDeployKeyNameAlreadyUsed{scope, name}
	}
	return nil
}

// UpdateDeployKeyLastUsed marks the key as used now.
func UpdateDeployKeyLastUsed(ctx context.Context, id int64) error {
	_, err := db.GetEngine(ctx).ID(id).Cols("updated_unix").Update(&DeployKey{UpdatedUnix: timeutil.TimeStampNow()})
	return err
}

// ListDeployKeysOptions are options for ListDeployKeys
type ListDeployKeysOptions struct {
	db.ListOptions
	Scope       Scope
	KeyID       int64
	Fingerprint string
}

func (opt ListDeployKeysOptions) ToOrders() string {
	return "name"
}

func (opt ListDeployKeysOptions) ToConds() builder.Cond {
	cond := opt.Scope.cond() // the scope must be used
	if opt.KeyID != 0 {
		cond = cond.And(builder.Eq{"key_id": opt.KeyID})
	}
	if opt.Fingerprint != "" {
		cond = cond.And(builder.Eq{"fingerprint": opt.Fingerprint})
	}
	return cond
}
