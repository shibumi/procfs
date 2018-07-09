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
					"sessionCount":       0,
					"sessions":           1,
					"shareReconnects":    0,
					"smbBuffer":          1,
					"smbPoolSize":        5,
					"smbSmallBuffer":     1,
					"smbSmallPoolSize":   30,
					"totalMaxOperations": 2,
					"totalOperations":    16,
				},
				SMB1Stats: []*cifs.SMB1Stats{
					&SMB1Stats{
						SessionIDs: cifs.SessionIDs{
							SessionID: 1,
							Server:    "server",
							Share:     "\\share",
						},
						Stats: map[string]uint64{
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
							"symlinks":    0,
							"t2Renames":   0,
							"writes":      0,
							"writesBytes": 0,
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
