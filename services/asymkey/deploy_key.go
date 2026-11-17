// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package asymkey

import (
	"context"
	"fmt"

	asymkey_model "gitea.dev/models/asymkey"
	"gitea.dev/models/db"
	deploykey_model "gitea.dev/models/deploykey"
	"gitea.dev/services/audit"
)

// DeleteDeployKeys deletes all deploy keys added to the scope. permissions check should be done outside
func DeleteDeployKeys(ctx context.Context, scope deploykey_model.Scope) (int, error) {
	deployKeys, err := db.Find[deploykey_model.DeployKey](ctx, deploykey_model.ListDeployKeysOptions{Scope: scope})
	if err != nil {
		return 0, fmt.Errorf("listDeployKeys: %w", err)
	}

	for _, dKey := range deployKeys {
		if err := deleteDeployKeyFromDB(ctx, dKey); err != nil {
			return 0, fmt.Errorf("deleteDeployKeys: %w", err)
		}
	}
	return len(deployKeys), nil
}

// deleteDeployKeyFromDB delete deploy keys from database
func deleteDeployKeyFromDB(ctx context.Context, key *deploykey_model.DeployKey) error {
	if _, err := db.DeleteByID[deploykey_model.DeployKey](ctx, key.ID); err != nil {
		return fmt.Errorf("delete deploy key [%d]: %w", key.ID, err)
	}

	if key.KeyType == deploykey_model.KeyTypeToken { // a token has no public key to clean up
		return nil
	}

	// Check if this is the last reference to same key content.
	has, err := deploykey_model.IsDeployKeyExistByPublicKeyID(ctx, key.KeyID)
	if err != nil {
		return err
	} else if !has {
		if _, err = db.DeleteByID[asymkey_model.PublicKey](ctx, key.KeyID); err != nil {
			return err
		}
	}

	return nil
}

// DeleteDeployKey deletes a deploy key of the scope and from the authorized_keys file if needed,
// and returns the key it deleted. Permissions check should be done outside.
func DeleteDeployKey(ctx context.Context, scope deploykey_model.Scope, id int64) (*deploykey_model.DeployKey, error) {
	deleted, err := db.WithTx2(ctx, func(ctx context.Context) (*deploykey_model.DeployKey, error) {
		key, err := deploykey_model.GetDeployKeyByID(ctx, scope, id)
		if err != nil {
			return nil, err
		}
		return key, deleteDeployKeyFromDB(ctx, key)
	})
	if err != nil {
		return nil, err
	}

	audit.RecordScopedByID(ctx, scope.OwnerID, scope.RepoID, audit.DeployKeyRemove, "deploy_key", deleted.Name)

	if deleted.KeyType == deploykey_model.KeyTypeToken {
		return deleted, nil // a token never appears in the authorized_keys file
	}

	return deleted, RewriteAllPublicKeys(ctx)
}
