// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package deploykey

import (
	"context"

	"gitea.dev/models/asymkey"
	"gitea.dev/models/db"
	"gitea.dev/models/perm"
	"gitea.dev/modules/util"

	"xorm.io/builder"
)

// AddDeployKeySSH add new deploy-key to database and authorized_keys file.
func AddDeployKeySSH(ctx context.Context, scope Scope, name, content string, accessMode perm.AccessMode) (*DeployKey, error) {
	if accessMode != perm.AccessModeRead && accessMode != perm.AccessModeWrite {
		return nil, util.NewInvalidArgumentErrorf("invalid access mode")
	}
	return db.WithTx2(ctx, func(ctx context.Context) (*DeployKey, error) {
		pkey, err := asymkey.FindOrAddDeployPublicKey(ctx, content)
		if err != nil {
			return nil, err
		}
		if has, err := db.Exist[DeployKey](ctx, scope.cond().And(builder.Eq{"key_id": pkey.ID})); err != nil {
			return nil, err
		} else if has {
			return nil, ErrDeployKeyAlreadyExist{pkey.ID, scope}
		}
		if err := checkDeployKeyName(ctx, scope, name); err != nil {
			return nil, err
		}

		key := &DeployKey{KeyID: pkey.ID, RepoID: scope.RepoID, OwnerID: scope.OwnerID, KeyType: KeyTypeSSH, Name: name, Fingerprint: pkey.Fingerprint, Mode: accessMode}
		return key, db.Insert(ctx, key)
	})
}

func (key *DeployKey) LoadPublicKey(ctx context.Context) (err error) {
	if key.PublicKey != nil {
		return nil
	}
	key.PublicKey, err = asymkey.GetPublicKeyByID(ctx, key.KeyID)
	return err
}

// GetDeployKeyByID returns the deploy-key with the given ID that was added to the scope.
func GetDeployKeyByID(ctx context.Context, scope Scope, deployKeyID int64) (*DeployKey, error) {
	key, exist, err := db.Get[DeployKey](ctx, scope.cond().And(builder.Eq{"id": deployKeyID}))
	if err != nil {
		return nil, err
	} else if !exist {
		return nil, ErrDeployKeyNotExist{deployKeyID, 0, scope}
	}
	return key, nil
}

// GetDeployKeyForRepo returns the deploy-key with the given ID if it reaches the repository.
func GetDeployKeyForRepo(ctx context.Context, repoID, ownerID, deployKeyID int64) (*DeployKey, error) {
	key, exist, err := db.Get[DeployKey](ctx, reachRepoCond(repoID, ownerID).And(builder.Eq{"id": deployKeyID}))
	if err != nil {
		return nil, err
	} else if !exist {
		return nil, ErrDeployKeyNotExist{deployKeyID, 0, Scope{RepoID: repoID}}
	}
	return key, nil
}

// GetDeployKeyByRepoPublicKey returns the deploy-key of the public key that reaches the repository.
// When the public key was added to the repository and to its owner, the one with the higher access mode wins.
func GetDeployKeyByRepoPublicKey(ctx context.Context, repoID, ownerID, publicKeyID int64) (*DeployKey, error) {
	key := &DeployKey{}
	// the type is part of the condition because every token row carries key id 0
	cond := reachRepoCond(repoID, ownerID).And(builder.Eq{"key_id": publicKeyID, "key_type": KeyTypeSSH})
	exist, err := db.GetEngine(ctx).Where(cond).Desc("mode").Get(key)
	if err != nil {
		return nil, err
	} else if !exist {
		return nil, ErrDeployKeyNotExist{0, publicKeyID, Scope{RepoID: repoID}}
	}
	return key, nil
}

// IsDeployKeyExistByPublicKeyID return true if there is at least one deploy-key with the key id
func IsDeployKeyExistByPublicKeyID(ctx context.Context, keyID int64) (bool, error) {
	return db.Exist[DeployKey](ctx, builder.Eq{"key_id": keyID, "key_type": KeyTypeSSH})
}
