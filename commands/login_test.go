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

package commands

import (
	"context"
	"crypto"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func MockPKToken(t *testing.T) (*pktoken.PKToken, crypto.Signer) {
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	providerOpts := providers.DefaultMockProviderOpts()
	op, _, idtTemplate, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)

	mockEmail := "arthur.aardvark@example.com"
	idtTemplate.ExtraClaims = map[string]any{
		"email": mockEmail,
	}

	client, err := client.New(op, client.WithSigner(signer, alg))
	require.NoError(t, err)

	pkt, err := client.Auth(context.Background())
	require.NoError(t, err)
	return pkt, signer
}

func TestCreateSSHCert(t *testing.T) {
	pkt, signer := MockPKToken(t)
	principals := []string{"guest", "dev"}

	sshCertBytes, signKeyBytes, err := createSSHCert(pkt, signer, principals)
	require.NoError(t, err)
	require.NotNil(t, sshCertBytes)
	require.NotNil(t, signKeyBytes)

	// Simple smoke test to verify we can parse the cert
	certPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte("certType" + " " + string(sshCertBytes)))
	require.NoError(t, err)
	require.NotNil(t, certPubkey)
}

func TestIdentityString(t *testing.T) {
	pkt, _ := MockPKToken(t)
	idString, err := IdentityString(*pkt)
	require.NoError(t, err)
	expIdString := "Email, sub, issuer, audience: \narthur.aardvark@example.com me https://accounts.example.com test_client_id"
	require.Equal(t, expIdString, idString)
}
