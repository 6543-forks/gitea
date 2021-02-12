// Copyright 2019 Gitea. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package models

import "code.gitea.io/gitea/modules/timeutil"

// ScheduledPullRequestMerge represents a pull request scheduled for merging when checks succeed
type ScheduledPullRequestMerge struct {
	ID          int64              `xorm:"pk autoincr"`
	PullID      int64              `xorm:"BIGINT"`
	DoerID      int64              `xorm:"BIGINT"`
	Doer        *User              `xorm:"-"`
	MergeStyle  MergeStyle         `xorm:"varchar(50)"`
	Message     string             `xorm:"TEXT"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
}

// ScheduleAutoMerge schedules a pull request to be merged when all checks succeed
func ScheduleAutoMerge(opts *ScheduledPullRequestMerge) (err error) {
	// Check if we already have a merge scheduled for that pull request
	exists, err := x.Exist(&ScheduledPullRequestMerge{PullID: opts.PullID})
	if err != nil {
		return
	}
	if exists {
		return ErrPullRequestAlreadyScheduledToAutoMerge{PullID: opts.PullID}
	}

	opts.DoerID = opts.Doer.ID

	if _, err = x.Insert(opts); err != nil {
		return
	}

	pr, err := GetPullRequestByID(opts.PullID)
	if err != nil {
		return err
	}

	_, err = CreateScheduledPRToAutoMergeComment(opts.Doer, pr)
	return err
}

// GetScheduledMergeRequestByPullID gets a scheduled pull request merge by pull request id
func GetScheduledMergeRequestByPullID(pullID int64) (exists bool, scheduledPRM *ScheduledPullRequestMerge, err error) {
	scheduledPRM = &ScheduledPullRequestMerge{}
	exists, err = x.Where("pull_id = ?", pullID).Get(scheduledPRM)
	if err != nil || !exists {
		return
	}
	scheduledPRM.Doer, err = getUserByID(x, scheduledPRM.DoerID)
	return
}

// RemoveScheduledMergeRequest cancels a previously scheduled pull request
func RemoveScheduledMergeRequest(scheduledPR *ScheduledPullRequestMerge) (err error) {
	if scheduledPR.ID == 0 && scheduledPR.PullID != 0 {
		_, err = x.Where("pull_id = ?", scheduledPR.PullID).Delete(&ScheduledPullRequestMerge{})
		return
	}
	_, err = x.Where("id = ? AND pull_id = ?", scheduledPR.ID, scheduledPR.PullID).Delete(&ScheduledPullRequestMerge{})
	return
}
