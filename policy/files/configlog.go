// Copyright 2025 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package files

import (
	"strings"
	"sync"
)

type ConfigProblem struct {
	Filepath      string
	OffendingLine string
	ErrorMessage  string
	Source        string
}

func (e ConfigProblem) String() string {
	return "encountered error: " + e.ErrorMessage + ", reading " + e.OffendingLine + " in " + e.Filepath
}

type ConfigLog struct {
	log      []ConfigProblem
	logMutex sync.Mutex
}

func (c *ConfigLog) RecordProblem(entry ConfigProblem) {
	c.logMutex.Lock()
	defer c.logMutex.Unlock()
	c.log = append(c.log, entry)
}

func (c *ConfigLog) GetProblems() []ConfigProblem {
	c.logMutex.Lock()
	defer c.logMutex.Unlock()
	logCopy := make([]ConfigProblem, len(c.log))
	copy(logCopy, c.log)
	return logCopy
}

func (c *ConfigLog) NoProblems() bool {
	c.logMutex.Lock()
	defer c.logMutex.Unlock()
	return len(c.log) == 0
}

func (c *ConfigLog) String() string {
	// No mutex needed since GetLogs handles the mutex
	logs := c.GetProblems()
	logsStrings := []string{}
	for _, log := range logs {
		logsStrings = append(logsStrings, log.String())
	}
	return strings.Join(logsStrings, "\n")
}

func (c *ConfigLog) Clear() {
	c.logMutex.Lock()
	defer c.logMutex.Unlock()
	c.log = []ConfigProblem{}
}

var (
	singleton *ConfigLog
	once      sync.Once
)

func ConfigProblems() *ConfigLog {
	once.Do(func() {
		singleton = &ConfigLog{
			log:      []ConfigProblem{},
			logMutex: sync.Mutex{},
		}
	})
	return singleton
}
