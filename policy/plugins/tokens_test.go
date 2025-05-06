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
		// {
		// 	name: "Happy path (all tokens)",
		// 	pkt: CreateMockPKToken(t, map[string]any{
		// 		"email":          "alice@gmail.com",
		// 		"email_verified": true,
		// 		"sub":            "1234",
		// 		"iss":            "https://accounts.example.com",
		// 		"aud":            "test_client_id",
		// 		"exp":            99999999999,
		// 		"nbf":            12345678900,
		// 		"iat":            99999999900,
		// 		"jti":            "abcdefg",
		// 		"groups":         []string{"admin", "user"},
		// 	}),
		// 	principal: "root",
		// 	sshCert:   b64("SSH certificate"),
		// 	keyType:   "ssh-rsa",
		// 	expectTokens: map[string]string{
		// 		"%{aud}":            "test_client_id",
		// 		"%{email}":          "alice@gmail.com",
		// 		"%{email_verified}": "true",
		// 		"%{exp}":            "-",
		// 		"%{groups}":         `["admin","user"]`,
		// 		"%{iat}":            "99999999900",
		// 		"%{idt}":            "-",
		// 		"%{iss}":            "https://accounts.example.com",
		// 		"%{jti}":            "abcdefg",
		// 		"%{k}":              b64("SSH certificate"),
		// 		"%{nbf}":            "12345678900",
		// 		"%{payload}":        "-",
		// 		"%{pkt}":            "-",
		// 		"%{sub}":            "1234",
		// 		"%{t}":              "ssh-rsa",
		// 		"%{u}":              "root",
		// 		"%{upk}":            "-",
		// 	},
		// },
		{
			name: "Happy path (minimal tokens)",
			pkt: CreateMockPKToken(t, map[string]any{
				"iat": 99999999900,
			}),
			principal: "root",
			sshCert:   b64("SSH certificate"),
			keyType:   "ssh-rsa",
			expectTokens: map[string]string{
				"%{aud}":            "test_client_id",
				"%{email}":          "",
				"%{email_verified}": "",
				"%{exp}":            "-",
				"%{groups}":         "",
				"%{iat}":            "99999999900",
				"%{idt}":            "-",
				"%{iss}":            "https://accounts.example.com",
				"%{jti}":            "",
				"%{k}":              b64("SSH certificate"),
				"%{nbf}":            "",
				"%{payload}":        "-",
				"%{pkt}":            "-",
				"%{sub}":            "me",
				"%{t}":              "ssh-rsa",
				"%{u}":              "root",
				"%{upk}":            "-",
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
				"%{aud}":            `["test_client_id","other_client_id"]`,
				"%{email}":          "",
				"%{email_verified}": "",
				"%{exp}":            "-",
				"%{groups}":         "",
				"%{iat}":            "99999999900",
				"%{idt}":            "-",
				"%{iss}":            "https://accounts.example.com",
				"%{jti}":            "",
				"%{k}":              b64("SSH certificate"),
				"%{nbf}":            "",
				"%{payload}":        "-",
				"%{pkt}":            "-",
				"%{sub}":            "me",
				"%{t}":              "ssh-rsa",
				"%{u}":              "root",
				"%{upk}":            "-",
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
			tokens, err := NewTokens(tt.pkt, tt.principal, tt.sshCert, tt.keyType)
			if tt.expectErrorString != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.expectErrorString)
			} else {
				require.NoError(t, err)
				require.NotNil(t, tokens)

				// Simple smoke test that these values where set. They are random so we check equality.
				require.Equal(t, len(strings.Split(tokens["%{pkt}"], ":")), 5)
				tokens["%{pkt}"] = "-"

				require.Equal(t, len(strings.Split(tokens["%{idt}"], ".")), 3)
				tokens["%{idt}"] = "-"

				require.Greater(t, len(tokens["%{upk}"]), 10)
				tokens["%{upk}"] = "-"

				require.Greater(t, len(tokens["%{payload}"]), 10)
				tokens["%{payload}"] = "-"

				require.Greater(t, len(tokens["%{exp}"]), 8)
				tokens["%{exp}"] = "-"

				require.Equal(t, tt.expectTokens, tokens)
			}
		})
	}
}
