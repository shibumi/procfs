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

package cifs

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/prometheus/procfs/internal/util"
)

// Array with fixed regex for parsing the SMB stats header
var regexpHeaders = [...]*regexp.Regexp{
	regexp.MustCompile(`CIFS Session: (?P<sessions>.*)`),
	regexp.MustCompile(`Share (unique mount targets): (?P<shares>.*)`),
	regexp.MustCompile(`SMB Request/Response Buffer: (?P<smbBuffer>.*) Pool Size: (?P<smbPoolSize>.*)`),
	regexp.MustCompile(`SMB Small Req/Resp Buffer: (?P<smbSmallBuffer>.*) Pool size: (?P<smbSmallPoolSize>.*)`),
	regexp.MustCompile(`Operations (MIDs): (?P<operations>.*)`),
	regexp.MustCompile(`(?P<sessionCount>.*) session (?P<shareReconnects>.*) share reconnects`),
	regexp.MustCompile(`Total vfs operations: (?P<totalOperations>.*) maximum at one time: (?P<totalMaxOperations>.*)`),
}

// Array with fixed regex for parsing SMB1
var regexpSMB1s = [...]*regexp.Regexp{
	regexp.MustCompile(`(?P<sessionID>.*)\) \\(?P<server>.*)\(?P<share>.*)`),
	regexp.MustCompile(`SMBs: (?P<smbs>.*) Oplocks breaks: (?P<breaks>.*)`),
	regexp.MustCompile(`Reads:  (?P<reads>.*) Bytes: (?P<readsBytes>.*)`),
	regexp.MustCompile(`Writes: (?P<writes>.*) Bytes: (?P<writesBytes>.*)`),
	regexp.MustCompile(`Flushes: (?P<flushes>.*)`),
	regexp.MustCompile(`Locks: (?P<locks>.*) HardLinks: (?P<hardlinks>.*) Symlinks: (?P<symlinks>.*)`),
	regexp.MustCompile(`Opens: (?P<opens>.*) Closes: (?P<closes>.*) Deletes: (?<deletes>.*)`),
	regexp.MustCompile(`Posix Opens: (?P<posixOpens>.*) Posix Mkdirs: (?P<posixMkdirs>.*)`),
	regexp.MustCompile(`Mkdirs: (?P<mkdirs>.*) Rmdirs: (?P<rmdirs>.*)`),
	regexp.MustCompile(`Renames: (?P<renames.*) T2 Renames (?<t2Renames>.*)`),
	regexp.MustCompile(`FindFirst: (?P<findFirst>.*) FNext (?P<fNext>.*) FClose (?P<fClose>.*)`),
}

// ParseClientStats returns stats read from /proc/fs/cifs/Stats
func ParseClientStats(r io.Reader) (*ClientStats, error) {
	stats := &ClientStats{}
	stats.Header = make(map[string]int)
	scanner := bufio.NewScanner(r)
	// Parse header
	for scanner.Scanner() {
		line := scanner.Text()
		for _, regexpHeader := range regexpHeaders {
			match := regexpHeader.FindStringSubmatch(line)
			if 0 == len(match) {
				continue
			}
			for index, name := range regexHeader.SubexpNames() {
				if 0 == index || "" == name {
					continue
				}
				value, _ := strconv.Atoi(match[index])
				if nil != err {
					continue
				}
				stats.Header[name] = value
			}
			break
		}
		if strings.hasPrefix(line, "Total vfs") {
			break
		}
	}
	// Parse Shares
	for scanner.Scan() {
		line := scanner.Text()
		for _, regexpSMB1 := range regexpSMB1s {
			match := regexpSMB1.FindStringSubmatch(line)
			if 0 == len(match) {
				continue
			}
			for index, name := range regexpSMB1.SubexpNames() {
				if 0 == index || "" == name {
					continue
				}
				if "sessionID" == name {
					stats.ShareStats = append(stats.ShareStats, make(map[string]int))
				} else {
					value, err := strconv.Atoi(match[index])
					if nil != err {
						continue
					}
					stats.ShareStats[len(stats.ShareStats)-1][name] = value
				}
			}
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning SMB file: %s", err)
	}

	return stats, nil
}
