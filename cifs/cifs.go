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

// model for the SMB1 statistics
type SMB1Stats struct {
	SessionID uint64
	Server    string
	Share     string
	Stats     map[string]uint64
}

// model for the CIFS header statistics
type ClientStats struct {
	Header    map[string]uint64
	SMB1Stats []*SMB1Stats
}
