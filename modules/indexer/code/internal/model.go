// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package internal

import "code.gitea.io/gitea/modules/timeutil"

type FileUpdate struct {
	Filename string `json:"filename"`
	BlobSha  string `json:"blob_sha"`
	Size     int64  `json:"size"`
	Sized    bool   `json:"sized"`
}

// RepoChanges changes (file additions/updates/removals) to a repo
type RepoChanges struct {
	Updates          []FileUpdate `json:"repo_updates"`
	RemovedFilenames []string     `json:"repo_removed_filenames"`
}

// IndexerData represents data stored in the code indexer
type IndexerData struct {
	RepoID int64 `json:"repo_id"`
}

// SearchResult result of performing a search in a repo
type SearchResult struct {
	RepoID      int64              `json:"repo_id"`
	StartIndex  int                `json:"start_index"`
	EndIndex    int                `json:"end_index"`
	Filename    string             `json:"filename"`
	Content     string             `json:"content"`
	CommitID    string             `json:"commit_id"`
	UpdatedUnix timeutil.TimeStamp `json:"updated_unix"`
	Language    string             `json:"language"`
	Color       string             `json:"color"`
}

// SearchResultLanguages result of top languages count in search results
type SearchResultLanguages struct {
	Language string `json:"language"`
	Color    string `json:"color"`
	Count    int    `json:"count"`
}
