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

func TestToTable(t *testing.T) {

	tests := []struct {
		name   string
		input  string
		output [][]string
	}{
		{
			name:   "empty",
			input:  "",
			output: [][]string{},
		},
		{
			name:   "multiple empty rows",
			input:  "\n     \n\n \n",
			output: [][]string{},
		},
		{
			name:   "commented out row",
			input:  "# this is a comment\n",
			output: [][]string{},
		},
		{
			name:   "multiple rows with comment",
			input:  "1 2 3\n 4 5#comment \n6 7 #comment\n 8",
			output: [][]string{{"1", "2", "3"}, {"4", "5"}, {"6", "7"}, {"8"}},
		},
		{
			name: "realistic input",
			input: `# Issuer Client-ID expiration-policy
https://accounts.google.com 206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com 24h
https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0 096ce0a3-5e72-4da8-9c86-12924b294a01 24h`,
			output: [][]string{
				{"https://accounts.google.com", "206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com", "24h"},
				{"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0", "096ce0a3-5e72-4da8-9c86-12924b294a01", "24h"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputBytes := []byte(tt.input)
			assert.Equal(t, tt.output, NewTable(inputBytes).GetRows())
		})
	}
}

func TestFieldsEscaped(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "simple space-separated words",
			input:    "hello world test",
			expected: []string{"hello", "world", "test"},
		},
		{
			name:     "escaped spaces",
			input:    `hello\ world test\ case`,
			expected: []string{"hello world", "test case"},
		},
		{
			name:     "escaped backslashes",
			input:    `hello\\world test\\case`,
			expected: []string{"hello\\world", "test\\case"},
		},
		{
			name:     "mixed escapes",
			input:    `hello\ world\\test case\\\ final`,
			expected: []string{"hello world\\test", "case\\ final"},
		},
		{
			name:     "multiple consecutive spaces",
			input:    "hello   world     test",
			expected: []string{"hello", "world", "test"},
		},
		{
			name:     "trailing escape",
			input:    `hello world\`,
			expected: []string{"hello", "world"},
		},
		{
			name:     "escaped special characters",
			input:    `hello\#world test\$case`,
			expected: []string{"hello#world", "test$case"},
		},
		{
			name:     "multiple escaped spaces",
			input:    `hello\ \ \ world`,
			expected: []string{"hello   world"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fieldsEscaped(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWriteEscaped(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected string
	}{
		{
			name:     "empty slice",
			input:    []string{},
			expected: "",
		},
		{
			name:     "single word",
			input:    []string{"hello"},
			expected: "hello",
		},
		{
			name:     "simple words",
			input:    []string{"hello", "world", "test"},
			expected: "hello world test",
		},
		{
			name:     "words with spaces",
			input:    []string{"hello world", "test case"},
			expected: `hello\ world test\ case`,
		},
		{
			name:     "words with backslashes",
			input:    []string{"hello\\world", "test\\case"},
			expected: `hello\\world test\\case`,
		},
		{
			name:     "mixed special characters",
			input:    []string{"hello world\\test", "case\\ final"},
			expected: `hello\ world\\test case\\\ final`,
		},
		{
			name:     "multiple spaces",
			input:    []string{"hello   world", "test"},
			expected: `hello\ \ \ world test`,
		},
		{
			name:     "special characters",
			input:    []string{"hello#world", "test$case"},
			expected: "hello#world test$case",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := writeEscaped(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRoundTrip tests that writeEscaped and fieldsEscaped work correctly together
func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input []string
	}{
		{
			name:  "empty slice",
			input: []string{},
		},
		{
			name:  "simple words",
			input: []string{"hello", "world", "test"},
		},
		{
			name:  "words with spaces",
			input: []string{"hello world", "test case", "final test"},
		},
		{
			name:  "words with backslashes",
			input: []string{"hello\\world", "test\\case", "final\\test"},
		},
		{
			name:  "mixed content",
			input: []string{"hello world\\test", "case\\ final", "test\\case space"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert to string and back to fields
			escaped := writeEscaped(tt.input)
			result := fieldsEscaped(escaped)

			// Check if the round trip preserves the original input
			assert.Equal(t, tt.input, result)
		})
	}
}
