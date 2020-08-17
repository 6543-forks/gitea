// Copyright 2020 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package models

import (
	"fmt"

	"code.gitea.io/gitea/modules/log"

	"xorm.io/xorm"
)

// ProjectIssue saves relation from issue to a project
type ProjectIssue struct {
	ID        int64  `xorm:"pk autoincr"`
	IssueID   int64  `xorm:"INDEX"`
	ProjectID int64  `xorm:"INDEX"`
	Priority  int    `xorm:"NOT NULL DEFAULT 0"`
	Issue     *Issue `xorm:"-"`

	// If 0, then it has not been added to a specific board in the project
	ProjectBoardID int64 `xorm:"INDEX"`
}

func deleteProjectIssuesByProjectID(e Engine, projectID int64) error {
	_, err := e.Where("project_id=?", projectID).Delete(&ProjectIssue{})
	return err
}

//  ___
// |_ _|___ ___ _   _  ___
//  | |/ __/ __| | | |/ _ \
//  | |\__ \__ \ |_| |  __/
// |___|___/___/\__,_|\___|

// LoadProject load the project the issue was assigned to
func (i *Issue) LoadProject() (err error) {
	return i.loadProject(x)
}

func (i *Issue) loadProject(e Engine) (err error) {
	if i.Project == nil {
		var p Project
		if _, err = e.Table("project").
			Join("INNER", "project_issue", "project.id=project_issue.project_id").
			Where("project_issue.issue_id = ?", i.ID).
			Get(&p); err != nil {
			return err
		}
		i.Project = &p
	}
	return
}

// ProjectID return project id if issue was assigned to one
func (i *Issue) ProjectID() int64 {
	return i.projectID(x)
}

func (i *Issue) projectID(e Engine) int64 {
	var ip ProjectIssue
	has, err := e.Where("issue_id=?", i.ID).Get(&ip)
	if err != nil || !has {
		return 0
	}
	return ip.ProjectID
}

// LoadProjectBoardID return project board id if issue was assigned to one
func (i *Issue) LoadProjectBoardID() int64 {
	return i.loadProjectBoardID(x)
}

func (i *Issue) loadProjectBoardID(e Engine) int64 {
	var ip ProjectIssue
	has, err := e.Where("issue_id=?", i.ID).Get(&ip)
	if err != nil || !has {
		return 0
	}
	return ip.ProjectBoardID
}

//  ____            _           _
// |  _ \ _ __ ___ (_) ___  ___| |_
// | |_) | '__/ _ \| |/ _ \/ __| __|
// |  __/| | | (_) | |  __/ (__| |_
// |_|   |_|  \___// |\___|\___|\__|
//               |__/

// NumIssues return counter of all issues assigned to a project
func (p *Project) NumIssues() int {
	c, err := x.Table("project_issue").
		Where("project_id=?", p.ID).
		GroupBy("issue_id").
		Cols("issue_id").
		Count()
	if err != nil {
		return 0
	}
	return int(c)
}

// NumClosedIssues return counter of closed issues assigned to a project
func (p *Project) NumClosedIssues() int {
	c, err := x.Table("project_issue").
		Join("INNER", "issue", "project_issue.issue_id=issue.id").
		Where("project_issue.project_id=? AND issue.is_closed=?", p.ID, true).
		Cols("issue_id").
		Count()
	if err != nil {
		return 0
	}
	return int(c)
}

// NumOpenIssues return counter of open issues assigned to a project
func (p *Project) NumOpenIssues() int {
	c, err := x.Table("project_issue").
		Join("INNER", "issue", "project_issue.issue_id=issue.id").
		Where("project_issue.project_id=? AND issue.is_closed=?", p.ID, false).Count("issue.id")
	if err != nil {
		return 0
	}
	return int(c)
}

// ChangeProjectAssign changes the project associated with an issue
func ChangeProjectAssign(issue *Issue, doer *User, newProjectID int64) error {

	sess := x.NewSession()
	defer sess.Close()
	if err := sess.Begin(); err != nil {
		return err
	}

	if err := addUpdateIssueProject(sess, issue, doer, newProjectID); err != nil {
		return err
	}

	return sess.Commit()
}

func addUpdateIssueProject(e *xorm.Session, issue *Issue, doer *User, newProjectID int64) error {
	oldProjectID := issue.projectID(e)
	if _, err := e.Where("project_issue.issue_id=?", issue.ID).Delete(&ProjectIssue{}); err != nil {
		return err
	}

	if err := issue.loadRepo(e); err != nil {
		return err
	}

	if oldProjectID > 0 || newProjectID > 0 {
		if _, err := createComment(e, &CreateCommentOptions{
			Type:         CommentTypeProject,
			Doer:         doer,
			Repo:         issue.Repo,
			Issue:        issue,
			OldProjectID: oldProjectID,
			ProjectID:    newProjectID,
		}); err != nil {
			return err
		}
	}

	var projectIssues []ProjectIssue
	if newProjectID != 0 {
		err := e.Where("issue_id = ? and project_id = ?", issue.ID, newProjectID).Find(&projectIssues)
		if err != nil {
			return err
		}
		if len(projectIssues) == 0 {
			_, err := e.Insert(&ProjectIssue{
				IssueID:   issue.ID,
				ProjectID: newProjectID,
			})
			return err
		}
	}
	return nil
}

//  ____            _           _   ____                      _
// |  _ \ _ __ ___ (_) ___  ___| |_| __ )  ___   __ _ _ __ __| |
// | |_) | '__/ _ \| |/ _ \/ __| __|  _ \ / _ \ / _` | '__/ _` |
// |  __/| | | (_) | |  __/ (__| |_| |_) | (_) | (_| | | | (_| |
// |_|   |_|  \___// |\___|\___|\__|____/ \___/ \__,_|_|  \__,_|
//               |__/

// MoveIssueAcrossProjectBoards move a card from one board to another
func MoveIssueAcrossProjectBoards(issue *Issue, board *ProjectBoard) error {

	sess := x.NewSession()
	defer sess.Close()
	if err := sess.Begin(); err != nil {
		return err
	}

	var pis ProjectIssue
	has, err := sess.Where("issue_id=?", issue.ID).Get(&pis)
	if err != nil {
		return err
	}

	if !has {
		return fmt.Errorf("issue has to be added to a project first")
	}

	pis.ProjectBoardID = board.ID
	if _, err := sess.ID(pis.ID).Cols("project_board_id").Update(&pis); err != nil {
		return err
	}

	return sess.Commit()
}

func (pb *ProjectBoard) removeIssues(e Engine) error {
	_, err := e.Exec("UPDATE `project_issue` SET project_board_id = 0 WHERE project_board_id = ? ", pb.ID)
	return err
}

// UpdateBoardIssuesPriority update given board issue priority
func UpdateBoardIssuesPriority(issues []ProjectIssue) ([]ProjectIssue, error) {
	sess := x.NewSession()
	if err := sess.Begin(); err != nil {
		var updatedIssues []ProjectIssue
		return updatedIssues, err
	}
	defer sess.Close()
	var updatedIssues []ProjectIssue
	for _, pissue := range issues {
		if pissue.ID != 0 {
			if _, err := sess.ID(pissue.ID).Cols("priority", "project_board_id").Update(&pissue); err != nil {
				log.Info("failed updating cards priorities %s", err)
				return updatedIssues, err
			}
			updatedIssues = append(updatedIssues, pissue)
		} else {
			var existingIssue ProjectIssue
			if found, err := sess.Where("issue_id = ? and project_id = ?", pissue.IssueID, pissue.ProjectID).
				Get(&existingIssue); err != nil {
				log.Error("failed finding issue %s", err)
			} else if !found {
				if _, err := sess.Insert(&pissue); err != nil {
					log.Info("failed inserting cards priorities %s", err)
					return updatedIssues, err
				}
				updatedIssues = append(updatedIssues, pissue)
			}
		}
	}
	return updatedIssues, sess.Commit()
}
