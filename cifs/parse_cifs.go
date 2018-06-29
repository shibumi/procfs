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
	"strings"
	"strconv"

	"github.com/prometheus/procfs/internal/util"
)


// ParseClientStats returns stats read from /proc/fs/cifs/Stats
func ParseClientStats(r io.Reader) (*ClientStats, error) {
	stats := &ClientStats{}
	stats.Header = make(map[string]uint64)
	scanner := bufio.NewScanner(r)
	// Parse header
	for scanner.Scan() {
		line := scanner.Text()
		for _, regexpHeader := range regexpHeaders {
			match := regexpHeader.FindStringSubmatch(line)
			if 0 == len(match) {
				continue
			}
			for index, name := range regexpHeader.SubexpNames() {
				if 0 == index || "" == name {
					continue
				}
				value, err := strconv.ParseUint(match[index], 10, 64)
				if nil != err {
					continue
				}
				stats.Header[name] = value
			}
			break
		}
		if strings.HasPrefix(line, "Total vfs") {
			break
		}
	}
	// Parse Shares
	var tmpSMB1Stats *SMB1Stats
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
				switch name {
				case "sessionID":
					tmpSMB1Stats = &SMB1Stats{
						Stats: make(map[string]uint64),
					}
					stats.ShareStatsSMB1 = append(stats.ShareStatsSMB1, tmpSMB1Stats)
					value, err := strconv.ParseUint(match[index], 10, 64)
					if nil != err {
						continue
					}
					tmpSMB1Stats.SessionID = value
				case "server":
					if "" != match[index] {
						tmpSMB1Stats.Server = match[index]
					}
				case "share":
					if "" != match[index] {
						tmpSMB1Stats.Share = match[index]
					}
				default:
					value, err := strconv.ParseUint(match[index], 10, 64)
					if nil != err {
						continue
					}
					tmpSMB1Stats.Stats[name] = value
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
