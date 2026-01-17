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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLog(t *testing.T) {

	tests := []struct {
		name          string
		clearWhenDone bool
		input         *[]ConfigProblem
		output        string
	}{
		{
			name:          "empty",
			clearWhenDone: true,
			input:         nil,
			output:        "",
		},
		{
			name:          "single entry",
			clearWhenDone: true,
			input: &[]ConfigProblem{
				{
					Filepath:      "/path/to/file",
					OffendingLine: "offending line",
					ErrorMessage:  "wrong number of arguments",
					Source:        "test 1",
				},
			},
			output: "encountered error: wrong number of arguments, reading offending line in /path/to/file",
		},
		{
			name:          "multiple entries",
			clearWhenDone: false,
			input: &[]ConfigProblem{
				{
					Filepath:      "/path/to/fileA",
					OffendingLine: "offending line 1",
					ErrorMessage:  "wrong number of arguments",
					Source:        "test 2",
				},
				{
					Filepath:      "/path/to/fileB",
					OffendingLine: "offending line 2",
					ErrorMessage:  "could not parse",
					Source:        "test 3",
				},
			},
			output: "encountered error: wrong number of arguments, reading offending line 1 in /path/to/fileA\nencountered error: could not parse, reading offending line 2 in /path/to/fileB",
		},
		{
			name:          "make sure that the log persists",
			clearWhenDone: true,
			input: &[]ConfigProblem{
				{
					Filepath:      "/path/to/filec",
					OffendingLine: "offending line 2",
					ErrorMessage:  "wrong number of arguments",
					Source:        "test 4",
				},
			},
			output: "encountered error: wrong number of arguments, reading offending line 1 in /path/to/fileA\nencountered error: could not parse, reading offending line 2 in /path/to/fileB\nencountered error: wrong number of arguments, reading offending line 2 in /path/to/filec",
		},
		{
			name:          "check clear",
			clearWhenDone: true,
			input:         nil,
			output:        "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configLog := ConfigProblems()

			if tt.input != nil {
				for _, entry := range *tt.input {
					configLog.RecordProblem(entry)
				}
			}
			assert.Equal(t, tt.output, configLog.String())
			if tt.clearWhenDone {
				configLog.Clear()
			}
		})
	}
}
