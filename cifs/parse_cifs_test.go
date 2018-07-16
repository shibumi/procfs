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

package cifs_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/prometheus/procfs/cifs"
)

func TestNewCifsRPCStats(t *testing.T) {
	tests := []struct {
		name    string
		content string
		stats   *cifs.ClientStats
		invalid bool
	}{
		{
			name:    "invalid file",
			content: "invalid",
			invalid: true,
		}, {
			name: "SMB1 statistics",
			content: `Resources in use
CIFS Session: 1
Share (unique mount targets): 2
SMB Request/Response Buffer: 1 Pool size: 5
SMB Small Req/Resp Buffer: 1 Pool size: 30
Operations (MIDs): 0

0 session 0 share reconnects
Total vfs operations: 16 maximum at one time: 2

1) \\server\share
SMBs: 9 Oplocks breaks: 0
Reads:  0 Bytes: 0
Writes: 0 Bytes: 0
Flushes: 0
Locks: 0 HardLinks: 0 Symlinks: 0
Opens: 0 Closes: 0 Deletes: 0
Posix Opens: 0 Posix Mkdirs: 0
Mkdirs: 0 Rmdirs: 0
Renames: 0 T2 Renames 0
FindFirst: 1 FNext 0 FClose 0`,
			stats: &cifs.ClientStats{
				Header: map[string]uint64{
					"operations":         0,
					"sessionCount":       0,
					"sessions":           1,
					"shareReconnects":    0,
					"shares":             2,
					"smbBuffer":          1,
					"smbPoolSize":        5,
					"smbSmallBuffer":     1,
					"smbSmallPoolSize":   30,
					"totalMaxOperations": 2,
					"totalOperations":    16,
				},
				SMB1Stats: []*cifs.SMB1Stats{
					&cifs.SMB1Stats{
						SessionIDs: cifs.SessionIDs{
							SessionID: 1,
							Server:    "server",
							Share:     "\\share",
						},
						Stats: map[string]uint64{
							"breaks":      0,
							"closes":      0,
							"deletes":     0,
							"fClose":      0,
							"fNext":       0,
							"findFirst":   1,
							"flushes":     0,
							"hardlinks":   0,
							"locks":       0,
							"mkdirs":      0,
							"opens":       0,
							"posixMkdirs": 0,
							"posixOpens":  0,
							"reads":       0,
							"readsBytes":  0,
							"renames":     0,
							"rmdirs":      0,
							"smbs":        9,
							"symlinks":    0,
							"t2Renames":   0,
							"writes":      0,
							"writesBytes": 0,
						},
					},
				},
			},
		}, {
			name: "SMB2 statistics",
			content: `Resources in use
CIFS Session: 2
Share (unique mount targets): 4
SMB Request/Response Buffer: 2 Pool size: 6
SMB Small Req/Resp Buffer: 2 Pool size: 30
Operations (MIDs): 0

0 session 0 share reconnects
Total vfs operations: 90 maximum at one time: 2

1) \\server\share1
SMBs: 20
Negotiates: 0 sent 0 failed
SessionSetups: 0 sent 0 failed
Logoffs: 0 sent 0 failed
TreeConnects: 0 sent 0 failed
TreeDisconnects: 0 sent 0 failed
Creates: 0 sent 2 failed
Closes: 0 sent 0 failed
Flushes: 0 sent 0 failed
Reads: 0 sent 0 failed
Writes: 0 sent 0 failed
Locks: 0 sent 0 failed
IOCTLs: 0 sent 0 failed
Cancels: 0 sent 0 failed
Echos: 0 sent 0 failed
QueryDirectories: 0 sent 0 failed
ChangeNotifies: 0 sent 0 failed
QueryInfos: 0 sent 0 failed
SetInfos: 0 sent 0 failed
OplockBreaks: 0 sent 0 failed`,
			stats: &cifs.ClientStats{
				Header: map[string]uint64{
					"operations":         0,
					"sessionCount":       0,
					"sessions":           2,
					"shareReconnects":    0,
					"shares":             4,
					"smbBuffer":          2,
					"smbPoolSize":        6,
					"smbSmallBuffer":     2,
					"smbSmallPoolSize":   30,
					"totalMaxOperations": 2,
					"totalOperations":    90,
				},
				SMB2Stats: []*cifs.SMB2Stats{
					&cifs.SMB2Stats{
						SessionIDs: cifs.SessionIDs{
							SessionID: 1,
							Server:    "server",
							Share:     "\\share1",
						},
						Stats: map[string]map[string]uint64{
							"Cancels": {
							"failed": 0,
							"sent": 0,
						},
						"ChangeNotifies": {
							"failed": 0,
							"sent": 0,
						},
						"Closes": {
							"failed": 0,
							"sent": 0,
						},
						"Creates": {
							"failed": 2,
							"sent": 0,
						},
						"Echos": {
							"failed": 0,
							"sent": 0,
						},
						"Flushes": {
							"failed": 0,
							"sent": 0,
						},
						"IOCTLs": {
							"failed": 0,
							"sent": 0,
						},
						"Locks": {
							"failed": 0,
							"sent": 0,
						},
						"Logoffs": {
							"failed": 0,
							"sent": 0,
						},
						"Negotiates": {
							"failed": 0,
							"sent": 0,
						},
						"OplockBreaks": {
							"failed": 0,
							"sent": 0,
						},
						"QueryDirectories": {
							"failed": 0,
							"sent": 0,
						},
						"QueryInfos": {
							"failed": 0,
							"sent": 0,
						},
						"Reads": {
							"failed": 0,
							"sent": 0,
						},
						"SessionSetups": {
							"failed": 0,
							"sent": 0,
						},
						"SetInfos": {
							"failed": 0,
							"sent": 0,
						},
						"TreeConnects": {
							"failed": 0,
							"sent": 0,
						},
						"TreeDisconnects": {
							"failed": 0,
							"sent": 0,
						},
						"Writes": {
							"failed": 0,
							"sent": 0,
						},
						"smbs": {
							"smbs": 20,
						},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats, err := cifs.ParseClientStats(strings.NewReader(tt.content))

			if tt.invalid && nil == err {
				t.Fatal("expected an error, but none occured")
			}
			if !tt.invalid && nil != err {
				t.Fatalf("unexpected error: %v", err)
			}
			if want, have := tt.stats, stats; !reflect.DeepEqual(want, have) {
				t.Fatalf("unexpected CIFS Stats:\nwant:\n%v\nhave:\n%v", want, have)
			}
		})
	}
}
