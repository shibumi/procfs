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
	"strconv"
)

func parseHeader(line string, header map[string]uint64) error {
	for _, regexpHeader := range regexpHeaders {
		match := regexpHeader.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		for index, name := range regexpHeader.SubexpNames() {
			if index == 0 || name == "" {
				continue
			}
			value, err := strconv.ParseUint(match[index], 10, 64)
			if err != nil {
				return fmt.Errorf("Invalid value in header")
			}
			header[name] = value
		}
	}
	return nil
}

func parseSessionIDs(line string, sessionIDs SessionIDs) (SessionIDs, error) {
	match := regexpSessionIDs.FindStringSubmatch(line)
	if match == nil {
		return sessionIDs, nil
	}
	for index, name := range regexpSessionIDs.SubexpNames() {
		if index == 0 || name == "" {
			continue
		}
		switch name {
		case "sessionID":
			value, err := strconv.ParseUint(match[index], 10, 64)
			if err != nil {
				return sessionIDs, fmt.Errorf("Invalid value for sessionID")
			}
			sessionIDs.SessionID = value
		case "server":
			if match[index] != "" {
				sessionIDs.Server = match[index]
			}
		case "share":
			if match[index] != "" {
				sessionIDs.Share = match[index]
			}
		default:
			return sessionIDs, nil
		}
	}
	return sessionIDs, nil
}

func parseSMB1(line string, smb1Stats map[string]uint64) error {
	for _, regexpSMB1 := range regexpSMB1s {
		match := regexpSMB1.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		for index, name := range regexpSMB1.SubexpNames() {
			if index == 0 || name == "" {
				continue
			}
			value, err := strconv.ParseUint(match[index], 10, 64)
			if err != nil {
				return fmt.Errorf("Invalid value in SMB1 statistics")
			}
			smb1Stats[name] = value
		}
	}
	return nil
}

func parseSMB2(line string, smb2Stats map[string]map[string]uint64) error {
	var keyword string
	for _, regexpSMB2 := range regexpSMB2s {
		match := regexpSMB2.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		for index, name := range regexpSMB2.SubexpNames() {
			if index == 0 || name == "" {
				continue
			}
			value, err := strconv.ParseUint(match[index], 10, 64)
			if err != nil {
				keyword = match[index]
				smb2Stats[keyword] = make(map[string]uint64)
				continue
			}
			smb2Stats[keyword][name] = value
		}
	}
	return nil
}

// ParseClientStats returns stats read from /proc/fs/cifs/Stats
func ParseClientStats(r io.Reader) (*ClientStats, error) {
	stats := &ClientStats{}
	stats.Header = make(map[string]uint64)
	smb1Stats := make(map[string]uint64)
	smb2Stats := make(map[string]map[string]uint64)
	scanner := bufio.NewScanner(r)
	var tmpSessionIDs SessionIDs
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parseHeader(line, stats.Header)
		tmpSessionIDs, _ := parseSessionIDs(line, tmpSessionIDs)
		parseSMB1(line, smb1Stats)
		parseSMB2(line, smb2Stats)
		fmt.Println(tmpSessionIDs)
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
