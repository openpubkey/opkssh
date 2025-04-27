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
		name    string
		input   string
		output  [][]string
		reverse string
	}{
		{
			name:    "empty",
			input:   "",
			output:  [][]string{},
			reverse: "",
		},
		{
			name:    "multiple empty rows",
			input:   "\n     \n\n \n",
			output:  [][]string{},
			reverse: "",
		},
		{
			name:    "commented out row",
			input:   "# this is a comment\n",
			output:  [][]string{},
			reverse: "",
		},
		{
			name:    "field with spaces",
			input:   "1 \"2 3\" 3\n",
			output:  [][]string{{"1", "2 3", "3"}},
			reverse: "1 '2 3' 3\n",
		},
		{
			name:    "field with spaces",
			input:   "1 'oidc:claims[\"https://example.com/my-custom-groups\"].contains(\"group with space and :\")' 3\n",
			output:  [][]string{{"1", "oidc:claims[\"https://example.com/my-custom-groups\"].contains(\"group with space and :\")", "3"}},
			reverse: "1 'oidc:claims[\"https://example.com/my-custom-groups\"].contains(\"group with space and :\")' 3\n",
		},
		{
			name:    "multiple rows with comment",
			input:   "1 2 3\n 4 5#comment \n6 7 #comment\n 8",
			output:  [][]string{{"1", "2", "3"}, {"4", "5"}, {"6", "7"}, {"8"}},
			reverse: "1 2 3\n4 5\n6 7\n8\n",
		},
		{
			name: "realistic input",
			input: "# Issuer Client-ID expiration-policy\n" +
				"https://accounts.google.com 206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com 24h\n" +
				"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0 096ce0a3-5e72-4da8-9c86-12924b294a01 24h",
			output: [][]string{
				{"https://accounts.google.com", "206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com", "24h"},
				{"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0", "096ce0a3-5e72-4da8-9c86-12924b294a01", "24h"},
			},
			reverse: "https://accounts.google.com 206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com 24h\n" +
				"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0 096ce0a3-5e72-4da8-9c86-12924b294a01 24h\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputBytes := []byte(tt.input)
			output := NewTable(inputBytes)

			reverse := output.ToString()

			assert.Equal(t, tt.output, output.GetRows())
			assert.Equal(t, tt.reverse, reverse)
		})
	}
}
