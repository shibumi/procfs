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
	regexp.MustCompile(`Opens: (?P<opens>\d+) Closes: (?P<closes>\d+) Deletes: (?<deletes>\d+)`),
	regexp.MustCompile(`Posix Opens: (?P<posixOpens>\d+) Posix Mkdirs: (?P<posixMkdirs>\d+)`),
	regexp.MustCompile(`Mkdirs: (?P<mkdirs>\d+) Rmdirs: (?P<rmdirs>\d+)`),
	regexp.MustCompile(`Renames: (?P<renames\d+) T2 Renames (?<t2Renames>\d+)`),
	regexp.MustCompile(`FindFirst: (?P<findFirst>\d+) FNext (?P<fNext>\d+) FClose (?P<fClose>\d+)`),
}

// Array with fixed regex for parsing SMB2
var regexpSMB2s = [...]*regexp.Regexp{
	regexp.MustCompile(`(?P<sessionID>\d+)\) \\\\(?P<server>[A-Za-z1-9-.]+)(?P<share>.+)`),
	regexp.MustCompile(`SMBs: (?P<smbs>\d+)`),
	regexp.MustCompile(`(?P<keyword>.*): (?P<sent>\d+) sent (?P<failed>\d+) failed`),
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
	var tmpSMB1Stats *SMB1Stats
	var tmpSMB2Stats *SMB2Stats
	var tmpSessionIDs *SessionIDs
	var sessionID uint64
	var server string
	var share string
	legacy := true
	for scanner.Scan() {
		line := scanner.Text()
		for _, regexpSMB1 := range regexpSMB1s {
			match := regexpSMB1.FindStringSubmatch(line)
			if 0 == len(match) {
				continue
			}
			if legacy {
				for index, name := range regexpSMB1.SubexpNames() {
					if 0 == index || "" == name {
						continue
					}
					value, err := strconv.Atoi(match[index])
					if nil != err {
						continue
					}
					switch name {
					case "sessionID":
						sessionID = value
						tmpSessionIDs := &SessionIDs
						tmpSMB1Stats := &SMB1Stats{
							Stats: make(map[string]uint64),
						}
						stats.SMB1Stats = append(stats.SMB1Stats, tmpSMB1Stats)
						tmpSMB1Stats.SessionId = value
					case "server":
						server = value
						tmpSMB1Stats.Server = value
					case "share":
						share = value
						tmpSMB1Stats.Server = value
					case "smbs":
						if len(match) > 1 {
							tmpSMB1Stats := &SMB1Stats{
								Stats: make(map[string]uint64),
							}
							stats.SMB1Stats = append(stats.SMB1Stats, tmpSMB1Stats)
							legacy = true
							stats.tmpSMB1Stats.Stats[len(stats.SMB1Stats)-1][name] = value
						} else if len(match) == 1 {
							tmpSMB2Stats := &SMB2Stats{
								Stats: make(map[string]map[string]uint64),
							}
							stats.SMB2Stats = append(stats.SMB2Stats, tmpSMB2Stats)
							legacy = false
						} else {
							continue
						}
					default:
						if "" == tmpSessionIDs.sessionID {
							tmpSessionIDs.SessionID = sessionID
							tmpSessionIDs.Server = server
							tmpSessionIDs.Share = share
						}
						stats.tmpSMB1Stats.Stats[len(stats.ShareStats)-1][name] = value
					}
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
