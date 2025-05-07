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

package plugins

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPercentExpand(t *testing.T) {
	base64OfExample := "ZXhhbXBsZQ=="
	base64OfExampleActual := base64.StdEncoding.EncodeToString([]byte("example"))
	require.Equal(t, base64OfExample, base64OfExampleActual)

	tokenTestMap := map[string]string{
		"%{u}": "uToken",
		"%{k}": "kToken",
		"%{t}": "tToken",

		"%{iss}":            "issToken",
		"%{sub}":            "subToken",
		"%{email}":          "emailToken",
		"%{email_verified}": "emailVerifiedToken",
		"%{aud}":            "audToken",
		"%{exp}":            "expToken",
		"%{nbf}":            "nbfToken",
		"%{iat}":            "iatToken",
		"%{jti}":            "jtiToken",

		"%{payload}": "payloadToken",
		"%{upk}":     "upkToken",
		"%{pkt}":     "pktToken",
		"%{idt}":     "idtToken",
		"%{idtRef}":  "idtRefToken",
		"%{config}":  "configToken",
	}

	tokenMapSemiRealisticValues := map[string]string{
		"%{u}": "root",
		"%{k}": b64("SSH certificate"),
		"%{t}": "ecdsa-sha2-nistp256-cert-v01@openssh.com",

		"%{iss}":            "https://example.com",
		"%{sub}":            "AAAAAAAAAAAAAAAAAAAAAJ8PFm0pjpXKQouYRalE11g",
		"%{email}":          "bd345b9c-6902-400d-9e18-45abdf0f698f",
		"%{email_verified}": "true",
		"%{aud}":            "bd345b9c-6902-400d-9e18-45abdf0f698f",
		"%{exp}":            "1737500954",
		"%{nbf}":            "1737414254",
		"%{iat}":            "1737414254",
		"%{jti}":            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",

		"%{payload}": b64(`{"iss":"https://example.com","sub":"1234"}`),
		"%{upk}":     b64(`example public key`),
		"%{pkt}":     "abcd:1234:efgh:5678:ijkl:9012:mnoq:3456",
		"%{idt}":     "abcd.1234.efgh",
		"%{idtRef}":  "abcd.1234.efgh",
		"%{config}": b64(`
name: Example Policy Command
command: /usr/bin/local/opk/policy-cmd %{sub} %{iss} %{aud}`),
	}

	tests := []struct {
		name            string
		tokens          map[string]string // File name to content mapping
		commandTemplate string
		expectedCommand []string
		errorExpected   string
	}{
		{
			name:            "Valid command template (smoke test)",
			tokens:          map[string]string{"%{token}": "word"},
			commandTemplate: `cmd %{token}`,
			expectedCommand: []string{"cmd", "word"},
		},
		{
			name:            "Valid command template (all tokens)",
			tokens:          tokenTestMap,
			commandTemplate: `cmd %{u} %{k} %{t} %{iss} %{sub} %{email} %{email_verified} %{aud} %{exp} %{nbf} %{iat} %{jti} %{payload} %{upk} %{pkt} %{idt} %{idtRef} %{config}`,
			expectedCommand: []string{"cmd", "uToken", "kToken", "tToken", "issToken", "subToken", "emailToken", "emailVerifiedToken", "audToken", "expToken", "nbfToken", "iatToken", "jtiToken", "payloadToken", "upkToken", "pktToken", "idtToken", "idtRefToken", "configToken"},
		},
		{
			name:            "Valid command template (all tokens realistic)",
			tokens:          tokenMapSemiRealisticValues,
			commandTemplate: `cmd %{u} %{k} %{t} %{iss} %{sub} %{email} %{email_verified} %{aud} %{exp} %{nbf} %{iat} %{jti} %{payload} %{upk} %{pkt} %{idt} %{idtRef} %{config}`,
			expectedCommand: []string{"cmd", "root", b64("SSH certificate"), "ecdsa-sha2-nistp256-cert-v01@openssh.com", "https://example.com", "AAAAAAAAAAAAAAAAAAAAAJ8PFm0pjpXKQouYRalE11g", "bd345b9c-6902-400d-9e18-45abdf0f698f", "true", "bd345b9c-6902-400d-9e18-45abdf0f698f", "1737500954", "1737414254", "1737414254", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzNCJ9", "ZXhhbXBsZSBwdWJsaWMga2V5", "abcd:1234:efgh:5678:ijkl:9012:mnoq:3456", "abcd.1234.efgh", "abcd.1234.efgh", b64(`
name: Example Policy Command
command: /usr/bin/local/opk/policy-cmd %{sub} %{iss} %{aud}`)},
		},
		{
			name:            "Valid command template (mixed args and tokens)",
			tokens:          tokenTestMap,
			commandTemplate: `/usr/bin/cmd --arg %{sub} --other-arg=%{iss} abcdef --arg3="%{email} %{iss}" %{pkt}`,
			expectedCommand: []string{"/usr/bin/cmd", "--arg", "subToken", "--other-arg=issToken", "abcdef", "--arg3=emailToken issToken", "pktToken"},
		},
		{
			name:            "Check we handle tokens that contain tokens",
			tokens:          map[string]string{"%{token}": "%{abcd}", "%{abc}": "123", "%{abcd}": "345"},
			commandTemplate: `cmd %{token} %{abcd} %{abc} %{abcd}`,
			expectedCommand: []string{"cmd", "%{abcd}", "345", "123", "345"},
		},
		{
			name:            "Check we escape percents",
			tokens:          map[string]string{"%{token}": "word", "%{token with escaped percent}": "escapedToken"},
			commandTemplate: `cmd %{token} %%token%% %%%{token with escaped percent}`,
			expectedCommand: []string{"cmd", "word", "%token%", "%escapedToken"},
		},
		{
			name:            "Error invalid token",
			tokens:          map[string]string{"%{yoken}": "word"},
			commandTemplate: `cmd %{othertoken}`,
			expectedCommand: nil,
			errorExpected:   "invalid token %{othertoken}",
		},
		{
			name:            "Error unmatched percent",
			tokens:          map[string]string{"%{token}": "word"},
			commandTemplate: `cmd %{token} %{abcdef`,
			expectedCommand: nil,
			errorExpected:   "unmatched { in at position (13) in command template: cmd %{token} %{abcdef",
		},
		{
			name:            "Error shell escape",
			tokens:          map[string]string{"%{token}": "word"},
			commandTemplate: `cmd "%{token}`,
			expectedCommand: nil,
			errorExpected:   "Unterminated double-quoted string",
		},
		{
			name:            "Spaces and other special characters in token",
			tokens:          map[string]string{"%{token}": "abc\n \n def"},
			commandTemplate: `cmd %{token}`,
			expectedCommand: []string{"cmd", "abc\n \n def"},
			errorExpected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			config := PluginConfig{
				Name:            "Example Policy Command",
				CommandTemplate: tt.commandTemplate,
			}
			command, err := config.PercentExpand(tt.tokens)
			if tt.errorExpected != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorExpected)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedCommand, command)
			}
		})
	}
}
