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
	"strconv"
	"strings"
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
	var tmpSMB2Stats *SMB2Stats
	var tmpSessionIDs *SessionIDs
	legacy := true
	for scanner.Scan() {
		line := scanner.Text()
		if legacy {
			for _, regexpSMB1 := range regexpSMB1s {
				match := regexpSMB1.FindStringSubmatch(line)
				if 0 == len(match) {
					if strings.HasPrefix(line, "SMBs:") && !(strings.Contains(line, "breaks")) {
						legacy = false
						tmpSMB2Stats = &SMB2Stats{
							Stats: make(map[string]map[string]uint64),
						}
						stats.SMB2Stats = append(stats.SMB2Stats, tmpSMB2Stats)
						re := regexp.MustCompile("[0-9]+")
						find_smb := re.FindAllString(line, 1)
						tmpSMB2Stats.Stats["smbs"] = make(map[string]uint64)
						value, err := strconv.ParseUint(find_smb[0], 10, 64)
						if nil != err {
							continue
						}
						tmpSMB2Stats.Stats["smbs"]["smbs"] = value
						break
					}
					continue
				}
				for index, name := range regexpSMB1.SubexpNames() {
					if 0 == index || "" == name {
						continue
					}
					switch name {
					case "sessionID":
						value, err := strconv.ParseUint(match[index], 10, 64)
						if nil != err {
							continue
						}
						tmpSessionIDs = &SessionIDs{
							SessionID: value,
						}
					case "server":
						if "" != match[index] {
							tmpSessionIDs.Server = match[index]
						}
					case "share":
						if "" != match[index] {
							tmpSessionIDs.Share = match[index]
						}
					case "smbs":
						tmpSMB1Stats = &SMB1Stats{
							Stats: make(map[string]uint64),
						}
						stats.SMB1Stats = append(stats.SMB1Stats, tmpSMB1Stats)
						value, err := strconv.ParseUint(match[index], 10, 64)
						if nil != err {
							continue
						}
						tmpSMB1Stats.Stats[name] = value
					default:
						value, err := strconv.ParseUint(match[index], 10, 64)
						if nil != err {
							continue
						}
						if 0 == tmpSMB1Stats.SessionIDs.SessionID {
							tmpSMB1Stats.SessionIDs.SessionID = tmpSessionIDs.SessionID
							tmpSMB1Stats.SessionIDs.Server = tmpSessionIDs.Server
							tmpSMB1Stats.SessionIDs.Share = tmpSessionIDs.Share

						}
						tmpSMB1Stats.Stats[name] = value
					}
				}
				break
			}
		} else {
			var keyword string
			for _, regexpSMB2 := range regexpSMB2s {
				match := regexpSMB2.FindStringSubmatch(line)
				if 0 == len(match) {
					if strings.HasPrefix(line, "SMBs:") && strings.Contains(line, "breaks") {
						legacy = true
						tmpSMB1Stats = &SMB1Stats{
							Stats: make(map[string]uint64),
						}
						stats.SMB1Stats = append(stats.SMB1Stats, tmpSMB1Stats)
						re := regexp.MustCompile("[0-9]+")
						find_smb := re.FindAllString(line, 2)
						smbs, err := strconv.ParseUint(find_smb[0], 10, 64)
						if nil != err {
							continue
						}
						breaks, err := strconv.ParseUint(find_smb[1], 10, 64)
						if nil != err {
							continue
						}
						tmpSMB1Stats.Stats["smbs"] = smbs
						tmpSMB1Stats.Stats["breaks"] = breaks

						break
					}
					continue
				}
				for index, name := range regexpSMB2.SubexpNames() {
					if 0 == index || "" == name {
						continue
					}
					switch name {
					case "sessionID":
						value, err := strconv.ParseUint(match[index], 10, 64)
						if nil != err {
							continue
						}
						tmpSessionIDs = &SessionIDs{
							SessionID: value,
						}
					case "server":
						if "" != match[index] {
							tmpSessionIDs.Server = match[index]
						}
					case "share":
						if "" != match[index] {
							tmpSessionIDs.Share = match[index]
						}
					case "smbs":
						tmpSMB2Stats = &SMB2Stats{
							Stats: make(map[string]map[string]uint64),
						}
						stats.SMB2Stats = append(stats.SMB2Stats, tmpSMB2Stats)
						value, err := strconv.ParseUint(match[index], 10, 64)
						if nil != err {
							continue
						}
						tmpSMB2Stats.Stats[name] = make(map[string]uint64)
						tmpSMB2Stats.Stats[name][name] = value

					default:
						value, err := strconv.ParseUint(match[index], 10, 64)
						if nil != err {
							keyword = match[index]
							tmpSMB2Stats.Stats[keyword] = make(map[string]uint64)
							continue
						}
						if 0 == tmpSMB2Stats.SessionIDs.SessionID {
							tmpSMB2Stats.SessionIDs.SessionID = tmpSessionIDs.SessionID
							tmpSMB2Stats.SessionIDs.Server = tmpSessionIDs.Server
							tmpSMB2Stats.SessionIDs.Share = tmpSessionIDs.Share

						}
						tmpSMB2Stats.Stats[keyword][name] = value
					}
				}
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning SMB file: %s", err)
	}

	if 0 == len(stats.Header) {
		// We should never have an empty Header. Otherwise the file is invalid
		return nil, fmt.Errorf("error scanning SMB file: header is empty")
	}
	return stats, nil
}
