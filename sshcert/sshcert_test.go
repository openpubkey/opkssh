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

package sshcert

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

var (
	caSecretKey = testkey(
		`-----BEGIN OPENSSH TEST KEY: DO NOT REPORT-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAzIUpmKvLqHofAXVc/HU4eA9niB3l9mWztelMaa7lB5PSPco+Yw48
bQgg8l3ehBfe2/aLSQgz2nrE+6E23jgtOav57BK3Zs3QIYqpZL8qvSR5xWSvq5wQc1Df+Q
rxdAK40vK4tutYzlIvYiaZu0B3TBxOCIwgcsfX6KJYRjwfhWgBg/Im2+eMsklAA9D3w4rD
kkdArQBnLSC7g2zc/Hi/qGSSDE/g6Y77A0X3Sez+VM5vDzbcer9YhCQVoWVL5s6hFObyqu
JQqTf4JqhSYNhHujNhsLzG2RsTgQkEjwZbEYGKXkKZnc0w7cTpfq0zKkuvuGyMEnyL/6zv
LjR5d68cywAAA8D9LxhQ/S8YUAAAAAdzc2gtcnNhAAABAQDMhSmYq8uoeh8BdVz8dTh4D2
eIHeX2ZbO16UxpruUHk9I9yj5jDjxtCCDyXd6EF97b9otJCDPaesT7oTbeOC05q/nsErdm
zdAhiqlkvyq9JHnFZK+rnBBzUN/5CvF0ArjS8ri261jOUi9iJpm7QHdMHE4IjCByx9fool
hGPB+FaAGD8ibb54yySUAD0PfDisOSR0CtAGctILuDbNz8eL+oZJIMT+DpjvsDRfdJ7P5U
zm8PNtx6v1iEJBWhZUvmzqEU5vKq4lCpN/gmqFJg2Ee6M2GwvMbZGxOBCQSPBlsRgYpeQp
mdzTDtxOl+rTMqS6+4bIwSfIv/rO8uNHl3rxzLAAAAAwEAAQAAAQBKOOlnprE6a1dlSBp+
5Guh5rVECNW0HiSiGBDLKdWkclkSY5tQh5IWX6TVUIu4lJEkcs0JrBhlabijOVaYPvrquy
bwLbqxbG/kPFZNYbM5AUvP/0JhnTm7H9aoovgNig9ZPw0aFT8dYWYg0LFp63NgA8WuBGyi
OzR4ELLIinlGCFqsR8W8C2E3dgogXqJQvaGg4Q+E9xjpxeiySl9eKQCtnul4kJ8tz7adIl
ntdTTpi2K1OkIWGt+jjuOFAe33Vq77ub3TxolIPfh+1COx1YJ4dlTSTZTScRIdX5W3bQZn
681Vi0hqpmtMPkJ7F++38HDJzbd5yaQTcv7m7pXBh7aBAAAAgGyx/CNr3vt+WJKukHu8DZ
naQ/B3lz4GNaJwed0sMpEKuaLXYoaefJKXVPq6hSimC9ScctzOKCizjQf20Goa96Jju4kt
Zerw6y9vgufGL9prXVyjuCyHs4sxwKyOew7QuQzpu3ArVGMCgTfZE9tn0Ga6FfcjgKxvuJ
k+KkoqblEzAAAAgQDnmzWHBeU0oXyMyPt4SeMozqcCkDY6pM+FZspf0zAYfLcrK4Tni74K
enV8+ZyjNPpfNAWZ6roNZQ4HUz5tLs2OMI4OxG+ptWDHbm3nppYqfg0Qcy7jl1NBBh9XNM
AwX2CwpoGpqcKWkcnH3/ZmN/8QIoTjl6uv6U0hLwBbVvFyyQAAAIEA4g+hppjyRW+G2WSW
nCfwQSQ15QL43hQVbPXwZiokEcmaueRjC0s6i/5tjKgnV8eQa9A0BdoxUa67DKCVvthUs/
mFplwGXA0qGsvlqL9TYCm2wA4VLFzXW9bxvPLqI+0WuB79qmZn4V64PSj6XYYPOGdWHw5k
uw2Z5widzugx6PMAAAAHdGVzdF9jYQECAwQ=
-----END OPENSSH TEST KEY: DO NOT REPORT-----`)

	caPubkey, _, _, _, _ = ssh.ParseAuthorizedKey([]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDMhSmYq8uoeh8BdVz8dTh4D2eIHeX2ZbO16UxpruUHk9I9yj5jDjxtCCDyXd6EF97b9otJCDPaesT7oTbeOC05q/nsErdmzdAhiqlkvyq9JHnFZK+rnBBzUN/5CvF0ArjS8ri261jOUi9iJpm7QHdMHE4IjCByx9foolhGPB+FaAGD8ibb54yySUAD0PfDisOSR0CtAGctILuDbNz8eL+oZJIMT+DpjvsDRfdJ7P5Uzm8PNtx6v1iEJBWhZUvmzqEU5vKq4lCpN/gmqFJg2Ee6M2GwvMbZGxOBCQSPBlsRgYpeQpmdzTDtxOl+rTMqS6+4bIwSfIv/rO8uNHl3rxzL test_ca"))

	testMsg    = []byte("1234")
	badTestMsg = []byte("123X")
)

func testkey(key string) []byte {
	return []byte(strings.ReplaceAll(key, "TEST KEY: DO NOT REPORT", "PRIVATE KEY"))
}

func newSshSignerFromPem(pemBytes []byte) (ssh.MultiAlgorithmSigner, error) {
	rawKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}
	sshSigner, err := ssh.NewSignerFromKey(rawKey)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerWithAlgorithms(sshSigner.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSASHA256})
}

func TestCASignerCreation(t *testing.T) {
	t.Parallel()

	caSigner, err := newSshSignerFromPem(caSecretKey)
	require.NoError(t, err)

	sshSig, err := caSigner.Sign(rand.Reader, testMsg)
	require.NoError(t, err)

	err = caPubkey.Verify(badTestMsg, sshSig)
	require.Error(t, err, "expected for signature to fail as the wrong message is used")
}

func TestInvalidSshPublicKey(t *testing.T) {
	// Test that the SSH cert smuggler cannot be constructed and returns an
	// error when given an SSH public key that isn't an SSH certificate
	t.Parallel()

	// Create SSH key that isn't a cert
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKey, err := ssh.NewPublicKey(&key.PublicKey)
	require.NoError(t, err)

	// Marshal the key in expected authorized_keys format and parse the values
	// needed to construct an SSH cert smuggler
	splitMarshalPubkey := strings.Split(string(ssh.MarshalAuthorizedKey(pubKey)), " ")
	require.Len(t, splitMarshalPubkey, 2)

	_, err = NewFromAuthorizedKey(splitMarshalPubkey[0], splitMarshalPubkey[1])
	require.Error(t, err)
}

func TestSshCertCreation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		mockEmail   string
		accessToken []byte
	}{
		{
			name:        "Happy Path (no access token)",
			mockEmail:   "arthur.aardvark@example.com",
			accessToken: nil,
		},
		{
			name:        "Happy Path (with access token)",
			mockEmail:   "arthur.aardvark@example.com",
			accessToken: []byte("expected-access-token"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEmail := "arthur.aardvark@example.com"

			providerOpts := providers.DefaultMockProviderOpts()
			op, _, idtTemplate, err := providers.NewMockProvider(providerOpts)
			require.NoError(t, err)

			idtTemplate.ExtraClaims = map[string]any{"email": mockEmail}

			client, err := client.New(op)
			require.NoError(t, err)

			pkt, err := client.Auth(context.Background())
			require.NoError(t, err)

			principals := []string{"guest", "dev"}
			certSmug, err := New(pkt, tt.accessToken, principals)
			require.NoError(t, err)

			pktSet, err := certSmug.GetPKToken()
			require.NotNil(t, pktSet)
			require.NoError(t, err)

			accessToken := certSmug.GetAccessToken()
			require.Equal(t, string(tt.accessToken), accessToken)

			pktVerifier, err := verifier.New(
				op,
			)
			require.NoError(t, err)
			pktRet, err := certSmug.VerifySshPktCert(context.Background(), *pktVerifier)
			require.NoError(t, err)
			require.NotNil(t, pktRet)
			require.Equal(t, pktSet, pktRet, "expected pktSet to be equal to pktRet")

			caSigner, err := newSshSignerFromPem(caSecretKey)
			require.NoError(t, err)

			sshCert, err := certSmug.SignCert(caSigner)
			require.NoError(t, err)

			err = certSmug.VerifyCaSig(caPubkey)
			require.NoError(t, err)

			checker := ssh.CertChecker{}
			err = checker.CheckCert("guest", sshCert)
			require.NoError(t, err)

			require.Equal(t, sshCert.KeyId, mockEmail, "expected KeyId to be (%s) but was (%s)", mockEmail, sshCert.KeyId)

			pktCom, ok := sshCert.Extensions["openpubkey-pkt"]
			require.True(t, ok, "expected to find openpubkey-pkt extension in sshCert")

			accessTokenInCert, ok := sshCert.Extensions["openpubkey-act"]
			if tt.accessToken != nil {
				require.True(t, ok, "expected to find openpubkey-act extension in sshCert")
				// Verify that the access token we set is in the cert
				require.Equal(t, string(tt.accessToken), accessTokenInCert, "expected openpubkey-act to match the one we set")

			} else {
				require.False(t, ok, "expected openpubkey-act (access token) extension to not be set in sshCert")
			}

			pktExt, err := pktoken.NewFromCompact([]byte(pktCom))
			require.NoError(t, err)

			cic, err := pktExt.GetCicValues()
			require.NoError(t, err)
			upk := cic.PublicKey()

			cryptoCertKey := (sshCert.Key.(ssh.CryptoPublicKey)).CryptoPublicKey()
			jwkCertKey, err := jwk.FromRaw(cryptoCertKey)
			require.NoError(t, err)
			if !jwk.Equal(upk, jwkCertKey) {
				t.Error(fmt.Errorf("expected upk to be equal to the value in sshCert.Key"))
			}
		})
	}
}
