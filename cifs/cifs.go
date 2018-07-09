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

import "regexp"

// model for the SMB1 statistics
type SMB1Stats struct {
	SessionIDs SessionIDs
	Stats      map[string]uint64
}

// model for SMB2 statistics
type SMB2Stats struct {
	SessionIDs SessionIDs
	Stats      map[string]map[string]uint64
}

type SessionIDs struct {
	SessionID uint64
	Server    string
	Share     string
}

// model for the CIFS header statistics
type ClientStats struct {
	Header    map[string]uint64
	SMB1Stats []*SMB1Stats
	SMB2Stats []*SMB2Stats
}

// Array with fixed regex for parsing the SMB stats header
var regexpHeaders = [...]*regexp.Regexp{
	regexp.MustCompile(`CIFS Session: (?P<sessions>\d+)`),
	regexp.MustCompile(`Share (unique mount targets): (?P<shares>\d+)`),
	regexp.MustCompile(`SMB Request/Response Buffer: (?P<smbBuffer>\d+) Pool Size: (?P<smbPoolSize>\d+)`),
	regexp.MustCompile(`SMB Small Req/Resp Buffer: (?P<smbSmallBuffer>\d+) Pool size: (?P<smbSmallPoolSize>\d+)`),
	regexp.MustCompile(`Operations (MIDs): (?P<operations>\d+)`),
	regexp.MustCompile(`(?P<sessionCount>\d+) session (?P<shareReconnects>\d+) share reconnects`),
	regexp.MustCompile(`Total vfs operations: (?P<totalOperations>\d+) maximum at one time: (?P<totalMaxOperations>\d+)`),
}

// Array with fixed regex for parsing SMB1
var regexpSMB1s = [...]*regexp.Regexp{
	regexp.MustCompile(`(?P<sessionID>\d+)\) \\\\(?P<server>[A-Za-z1-9-.]+)(?P<share>.+)`),
	regexp.MustCompile(`SMBs: (?P<smbs>\d+) Oplocks breaks: (?P<breaks>\d+)`),
	regexp.MustCompile(`Reads:  (?P<reads>\d+) Bytes: (?P<readsBytes>\d+)`),
	regexp.MustCompile(`Writes: (?P<writes>\d+) Bytes: (?P<writesBytes>\d+)`),
	regexp.MustCompile(`Flushes: (?P<flushes>\d+)`),
	regexp.MustCompile(`Locks: (?P<locks>\d+) HardLinks: (?P<hardlinks>\d+) Symlinks: (?P<symlinks>\d+)`),
	regexp.MustCompile(`Opens: (?P<opens>\d+) Closes: (?P<closes>\d+) Deletes: (?P<deletes>\d+)`),
	regexp.MustCompile(`Posix Opens: (?P<posixOpens>\d+) Posix Mkdirs: (?P<posixMkdirs>\d+)`),
	regexp.MustCompile(`Mkdirs: (?P<mkdirs>\d+) Rmdirs: (?P<rmdirs>\d+)`),
	regexp.MustCompile(`Renames: (?P<renames>\d+) T2 Renames (?P<t2Renames>\d+)`),
	regexp.MustCompile(`FindFirst: (?P<findFirst>\d+) FNext (?P<fNext>\d+) FClose (?P<fClose>\d+)`),
}

// Array with fixed regex for parsing SMB2
var regexpSMB2s = [...]*regexp.Regexp{
	regexp.MustCompile(`(?P<sessionID>\d+)\) \\\\(?P<server>[A-Za-z1-9-.]+)(?P<share>.+)`),
	regexp.MustCompile(`SMBs: (?P<smbs>\d+)`),
	regexp.MustCompile(`(?P<keyword>.*): (?P<sent>\d+) sent (?P<failed>\d+) failed`),
}