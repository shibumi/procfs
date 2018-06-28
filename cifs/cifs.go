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

// Header model of /proc/fs/cifs/Stats
type Header struct {
	Sessions           uint64
	Shares             uint64
	SMBBuffer          uint64
	SMBPoolSize        uint64
	SMBSmallBuffer     uint64
	SMBSmallPoolSize   uint64
	Operations         uint64
	SessionCount       uint64
	ShareReconnects    uint64
	TotalOperations    uint64
	TotalMaxOperations uint64
}

// model for the ClientStats
type ClientStats struct {
	Header     Header
	ShareStats []map[string]int
}
