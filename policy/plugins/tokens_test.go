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
	"context"
	"strings"
	"testing"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/stretchr/testify/require"
)

func CreateMockPKToken(t *testing.T, claims map[string]any) *pktoken.PKToken {
	providerOpts := providers.DefaultMockProviderOpts()
	op, _, idtTemplate, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)

	idtTemplate.ExtraClaims = claims

	client, err := client.New(op)
	require.NoError(t, err)

	pkt, err := client.Auth(context.Background())
	require.NoError(t, err)
	return pkt
}

func TestNewTokens(t *testing.T) {
	tests := []struct {
		name              string
		pkt               *pktoken.PKToken
		principal         string
		sshCert           string
		keyType           string
		expectTokens      map[string]string
		expectErrorString string
	}{
		{
			name: "Happy path (all tokens)",
			pkt: CreateMockPKToken(t, map[string]any{
				"email":          "alice@gmail.com",
				"email_verified": true,
				"sub":            "1234",
				"iss":            "https://accounts.example.com",
				"aud":            "test_client_id",
				"exp":            99999999999,
				"nbf":            12345678900,
				"iat":            99999999900,
				"jti":            "abcdefg",
				"groups":         []string{"admin", "user"},
			}),
			principal: "root",
			sshCert:   b64("SSH certificate"),
			keyType:   "ssh-rsa",
			expectTokens: map[string]string{
				"OPKSSH_PLUGIN_AUD":            "test_client_id",
				"OPKSSH_PLUGIN_EMAIL":          "alice@gmail.com",
				"OPKSSH_PLUGIN_EMAIL_VERIFIED": "true",
				"OPKSSH_PLUGIN_EXP":            "-",
				"OPKSSH_PLUGIN_GROUPS":         `["admin","user"]`,
				"OPKSSH_PLUGIN_IAT":            "99999999900",
				"OPKSSH_PLUGIN_IDT":            "-",
				"OPKSSH_PLUGIN_ISS":            "https://accounts.example.com",
				"OPKSSH_PLUGIN_JTI":            "abcdefg",
				"OPKSSH_PLUGIN_K":              b64("SSH certificate"),
				"OPKSSH_PLUGIN_NBF":            "12345678900",
				"OPKSSH_PLUGIN_PAYLOAD":        "-",
				"OPKSSH_PLUGIN_PKT":            "-",
				"OPKSSH_PLUGIN_SUB":            "1234",
				"OPKSSH_PLUGIN_T":              "ssh-rsa",
				"OPKSSH_PLUGIN_U":              "root",
				"OPKSSH_PLUGIN_UPK":            "-",
			},
		},
		{
			name: "Happy path (minimal tokens)",
			pkt: CreateMockPKToken(t, map[string]any{
				"iat": 99999999900,
			}),
			principal: "root",
			sshCert:   b64("SSH certificate"),
			keyType:   "ssh-rsa",
			expectTokens: map[string]string{
				"OPKSSH_PLUGIN_AUD":            "test_client_id",
				"OPKSSH_PLUGIN_EMAIL":          "",
				"OPKSSH_PLUGIN_EMAIL_VERIFIED": "",
				"OPKSSH_PLUGIN_EXP":            "-",
				"OPKSSH_PLUGIN_GROUPS":         "",
				"OPKSSH_PLUGIN_IAT":            "99999999900",
				"OPKSSH_PLUGIN_IDT":            "-",
				"OPKSSH_PLUGIN_ISS":            "https://accounts.example.com",
				"OPKSSH_PLUGIN_JTI":            "",
				"OPKSSH_PLUGIN_K":              b64("SSH certificate"),
				"OPKSSH_PLUGIN_NBF":            "",
				"OPKSSH_PLUGIN_PAYLOAD":        "-",
				"OPKSSH_PLUGIN_PKT":            "-",
				"OPKSSH_PLUGIN_SUB":            "me",
				"OPKSSH_PLUGIN_T":              "ssh-rsa",
				"OPKSSH_PLUGIN_U":              "root",
				"OPKSSH_PLUGIN_UPK":            "-",
			},
		},
		{
			name: "Happy path (string list audience)",
			pkt: CreateMockPKToken(t, map[string]any{
				"iat": 99999999900,
				"aud": []string{"test_client_id", "other_client_id"},
			}),
			principal: "root",
			sshCert:   b64("SSH certificate"),
			keyType:   "ssh-rsa",
			expectTokens: map[string]string{
				"OPKSSH_PLUGIN_AUD":            `["test_client_id","other_client_id"]`,
				"OPKSSH_PLUGIN_EMAIL":          "",
				"OPKSSH_PLUGIN_EMAIL_VERIFIED": "",
				"OPKSSH_PLUGIN_EXP":            "-",
				"OPKSSH_PLUGIN_GROUPS":         "",
				"OPKSSH_PLUGIN_IAT":            "99999999900",
				"OPKSSH_PLUGIN_IDT":            "-",
				"OPKSSH_PLUGIN_ISS":            "https://accounts.example.com",
				"OPKSSH_PLUGIN_JTI":            "",
				"OPKSSH_PLUGIN_K":              b64("SSH certificate"),
				"OPKSSH_PLUGIN_NBF":            "",
				"OPKSSH_PLUGIN_PAYLOAD":        "-",
				"OPKSSH_PLUGIN_PKT":            "-",
				"OPKSSH_PLUGIN_SUB":            "me",
				"OPKSSH_PLUGIN_T":              "ssh-rsa",
				"OPKSSH_PLUGIN_U":              "root",
				"OPKSSH_PLUGIN_UPK":            "-",
			},
		},
		{
			name: "Wrong type for email_verified claim in ID token",
			pkt: CreateMockPKToken(t, map[string]any{
				"email_verified": 1234,
			}),
			principal:         "root",
			sshCert:           b64("SSH certificate"),
			keyType:           "ssh-rsa",
			expectErrorString: "error unmarshalling pk token payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := PopulatePluginEnvVars(tt.pkt, tt.principal, tt.sshCert, tt.keyType)
			if tt.expectErrorString != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.expectErrorString)
			} else {
				require.NoError(t, err)
				require.NotNil(t, tokens)

				// Simple smoke test that these values where set. They are random so we check equality.
				require.Equal(t, len(strings.Split(tokens["OPKSSH_PLUGIN_PKT"], ":")), 5)
				tokens["OPKSSH_PLUGIN_PKT"] = "-"

				require.Equal(t, len(strings.Split(tokens["OPKSSH_PLUGIN_IDT"], ".")), 3)
				tokens["OPKSSH_PLUGIN_IDT"] = "-"

				require.Greater(t, len(tokens["OPKSSH_PLUGIN_UPK"]), 10)
				tokens["OPKSSH_PLUGIN_UPK"] = "-"

				require.Greater(t, len(tokens["OPKSSH_PLUGIN_PAYLOAD"]), 10)
				tokens["OPKSSH_PLUGIN_PAYLOAD"] = "-"

				require.Greater(t, len(tokens["OPKSSH_PLUGIN_EXP"]), 8)
				tokens["OPKSSH_PLUGIN_EXP"] = "-"

				require.Equal(t, tt.expectTokens, tokens)
			}
		})
	}
}
