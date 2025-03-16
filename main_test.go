// Copyright 2024 OpenPubkey
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

package main

import (
	"errors"
	"testing"
)

func TestIsOpenSSHVersion8Dot1OrGreater(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantIsGreater bool
		wantErr       error
	}{
		{
			name:          "Exact 8.1",
			input:         "OpenSSH_8.1",
			wantIsGreater: true,
			wantErr:       nil,
		},
		{
			name:          "Above 8.1 (8.4)",
			input:         "OpenSSH_8.4",
			wantIsGreater: true,
			wantErr:       nil,
		},
		{
			name:          "Above 8.1 with patch (9.9p1)",
			input:         "OpenSSH_9.9p1",
			wantIsGreater: true,
			wantErr:       nil,
		},
		{
			name:          "Below 8.1 (7.9)",
			input:         "OpenSSH_7.9",
			wantIsGreater: false,
			wantErr:       nil,
		},
		{
			name:          "Multiple dotted version above 8.1 (8.1.2)",
			input:         "OpenSSH_8.1.2",
			wantIsGreater: true,
			wantErr:       nil,
		},
		{
			name:          "Multiple dotted version below 8.1 (7.10.3)",
			input:         "OpenSSH_7.10.3",
			wantIsGreater: false,
			wantErr:       nil,
		},
		{
			name:          "Malformed version string",
			input:         "OpenSSH_, something not right",
			wantIsGreater: false,
			wantErr:       errors.New("invalid OpenSSH version"),
		},
		{
			name:          "No OpenSSH prefix at all",
			input:         "Completely invalid input",
			wantIsGreater: false,
			wantErr:       errors.New("invalid OpenSSH version"),
		},
		{
			name:          "Includes trailing info (8.2, Raspbian-1)",
			input:         "OpenSSH_8.2, Raspbian-1",
			wantIsGreater: true,
			wantErr:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIsGreater, gotErr := isOpenSSHVersion8Dot1OrGreater(tt.input)

			if gotIsGreater != tt.wantIsGreater {
				t.Errorf(
					"isOpenSSHVersion8Dot1OrGreater(%q) got %v; want %v",
					tt.input,
					gotIsGreater,
					tt.wantIsGreater,
				)
			}

			if (gotErr != nil) != (tt.wantErr != nil) {
				t.Errorf(
					"isOpenSSHVersion8Dot1OrGreater(%q) error = %v; want %v",
					tt.input,
					gotErr,
					tt.wantErr,
				)
			} else if gotErr != nil && tt.wantErr != nil {
				if gotErr.Error() != tt.wantErr.Error() {
					t.Errorf("Unexpected error message. got %q; want %q",
						gotErr.Error(), tt.wantErr.Error())
				}
			}
		})
	}
}
