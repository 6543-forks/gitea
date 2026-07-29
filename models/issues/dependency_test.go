// Copyright 2018 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package issues_test

import (
	"testing"

	"gitea.dev/models/db"
	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	unit_model "gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"

	"github.com/stretchr/testify/assert"
)

func TestCreateIssueDependency(t *testing.T) {
	// Prepare
	assert.NoError(t, unittest.PrepareTestDatabase())

	user1, err := user_model.GetUserByID(t.Context(), 1)
	assert.NoError(t, err)

	issue1, err := issues_model.GetIssueByID(t.Context(), 1)
	assert.NoError(t, err)

	issue2, err := issues_model.GetIssueByID(t.Context(), 2)
	assert.NoError(t, err)

	// Create a dependency and check if it was successful
	err = issues_model.CreateIssueDependency(t.Context(), user1, issue1, issue2)
	assert.NoError(t, err)

	// Do it again to see if it will check if the dependency already exists
	err = issues_model.CreateIssueDependency(t.Context(), user1, issue1, issue2)
	assert.Error(t, err)
	assert.True(t, issues_model.IsErrDependencyExists(err))

	// Check for circular dependencies
	err = issues_model.CreateIssueDependency(t.Context(), user1, issue2, issue1)
	assert.Error(t, err)
	assert.True(t, issues_model.IsErrCircularDependency(err))

	_ = unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{Type: issues_model.CommentTypeAddDependency, PosterID: user1.ID, IssueID: issue1.ID})

	// Check if dependencies left is correct
	left, err := issues_model.IssueNoDependenciesLeft(t.Context(), issue1)
	assert.NoError(t, err)
	assert.False(t, left)

	// Close #2 and check again
	_, err = issues_model.CloseIssue(t.Context(), issue2, user1)
	assert.NoError(t, err)

	issue2Closed, err := issues_model.GetIssueByID(t.Context(), 2)
	assert.NoError(t, err)
	assert.True(t, issue2Closed.IsClosed)

	left, err = issues_model.IssueNoDependenciesLeft(t.Context(), issue1)
	assert.NoError(t, err)
	assert.True(t, left)

	// Test removing the dependency
	err = issues_model.RemoveIssueDependency(t.Context(), user1, issue1, issue2, issues_model.DependencyTypeBlockedBy)
	assert.NoError(t, err)

	_, err = issues_model.ReopenIssue(t.Context(), issue2, user1)
	assert.NoError(t, err)

	issue2Reopened, err := issues_model.GetIssueByID(t.Context(), 2)
	assert.NoError(t, err)
	assert.False(t, issue2Reopened.IsClosed)
}

// enableRepoDependencies turns on the issue-dependency feature for a repository,
// which the fixtures leave disabled.
func enableRepoDependencies(t *testing.T, repoID int64) {
	t.Helper()

	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repoID})
	repoUnit, err := repo.GetUnit(t.Context(), unit_model.TypeIssues)
	assert.NoError(t, err)

	repoUnit.IssuesConfig().EnableDependencies = true
	_, err = db.GetEngine(t.Context()).ID(repoUnit.ID).Cols("config").Update(repoUnit)
	assert.NoError(t, err)
}

func TestSetIssueAsClosedWithDependencies(t *testing.T) {
	// repo 1 holds both an open issue (#1) and an open pull request (#2)
	t.Run("PullRequestClosableWhileBlocked", func(t *testing.T) {
		assert.NoError(t, unittest.PrepareTestDatabase())
		enableRepoDependencies(t, 1)

		user1, err := user_model.GetUserByID(t.Context(), 1)
		assert.NoError(t, err)
		pull, err := issues_model.GetIssueByID(t.Context(), 2)
		assert.NoError(t, err)
		assert.True(t, pull.IsPull)
		blocker, err := issues_model.GetIssueByID(t.Context(), 1)
		assert.NoError(t, err)
		assert.False(t, blocker.IsClosed)

		assert.NoError(t, issues_model.CreateIssueDependency(t.Context(), user1, pull, blocker))
		noDeps, err := issues_model.IssueNoDependenciesLeft(t.Context(), pull)
		assert.NoError(t, err)
		assert.False(t, noDeps)

		// dependencies gate merging a pull request, not closing it
		_, err = issues_model.CloseIssue(t.Context(), pull, user1)
		assert.NoError(t, err)

		reloaded, err := issues_model.GetIssueByID(t.Context(), 2)
		assert.NoError(t, err)
		assert.True(t, reloaded.IsClosed)
	})

	t.Run("IssueStillBlocked", func(t *testing.T) {
		assert.NoError(t, unittest.PrepareTestDatabase())
		enableRepoDependencies(t, 1)

		user1, err := user_model.GetUserByID(t.Context(), 1)
		assert.NoError(t, err)
		issue, err := issues_model.GetIssueByID(t.Context(), 1)
		assert.NoError(t, err)
		assert.False(t, issue.IsPull)
		blocker, err := issues_model.GetIssueByID(t.Context(), 2)
		assert.NoError(t, err)
		assert.False(t, blocker.IsClosed)

		assert.NoError(t, issues_model.CreateIssueDependency(t.Context(), user1, issue, blocker))

		_, err = issues_model.CloseIssue(t.Context(), issue, user1)
		assert.Error(t, err)
		assert.True(t, issues_model.IsErrDependenciesLeft(err))

		reloaded, err := issues_model.GetIssueByID(t.Context(), 1)
		assert.NoError(t, err)
		assert.False(t, reloaded.IsClosed)
	})
}
