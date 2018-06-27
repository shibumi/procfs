// Copyright 2018 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package cifs implements parsing of /proc/fs/cifs/Stats
// Fields are documented in https://www.kernel.org/doc/readme/Documentation-filesystems-cifs-README

package cifs

// General models the general information header of /proc/fs/cifs/Stats
type General struct {
	Sessions                 uint64
	Shares                   uint64
	SMBBuffers               uint64
	SMBPoolSize              uint64
	SMBSmallBuffers          uint64
	SMBSmallPoolSize         uint64
	Operations               uint64
	ShareReconnects          uint64
	TotalOperations          uint64
	TotalOperationsAtOneTime uint64
}

// ShareStats models the statistics for each share
type ShareStats struct {
	Path        string
	SMBs        uint64
	Reads       uint64
	ReadsBytes  uint64
	WritesBytes uint64
	Writes      uint64
	Flushes     uint64
	Locks       uint64
	HardLinks   uint64
	Symlinks    uint64
	Opens       uint64
	Closes      uint64
	Deletes     uint64
	PosixOpens  uint64
	PosixMkdirs uint64
	Mkdirs      uint64
	Rmdirs      uint64
	Renames     uint64
	T2Renames   uint64
	FindFirst   uint64
	FNext       uint64
	FClose      uint64
}

// ClientStats
type ClientStats struct {
	General    General
	ShareStats []ShareStats
}
