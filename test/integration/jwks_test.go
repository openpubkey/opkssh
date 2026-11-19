// Copyright 2026 OpenPubkey
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

//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/opkssh/commands"
	"github.com/openpubkey/opkssh/policy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

// helloEd25519Key is a key from hello.coop's JWKS (#655). Its alg is the
// RFC 9864 name "Ed25519" rather than "EdDSA".
const helloEd25519Key = `{"key_ops":["verify"],"alg":"Ed25519","crv":"Ed25519","x":"N1o1oa4UcCLJAMZYA5L2ViNxKZikzeCNFCjl7UdpCAM","kty":"OKP","kid":"2026-10-04T22:58:52.632Z_1a2-75b-Ed25519","use":"sig"}`

// TestLoginAndVerifyWithEd25519AlgInJwks checks that an "Ed25519" key in the
// provider's JWKS, as hello.coop publishes, doesn't stop login or verify from
// using the provider's other keys.
func TestLoginAndVerifyWithEd25519AlgInJwks(t *testing.T) {
	opServer, err := NewFakeOpServer(WithExtraJwksKeys(helloEd25519Key))
	require.NoError(t, err)
	defer opServer.Close()

	keyPath := filepath.Join(t.TempDir(), "id_ecdsa")
	loginWithFakeOp(t, opServer, keyPath)

	pubKey, _, err := GetOPKSshKey(keyPath)
	require.NoError(t, err)

	providerPolicy := &policy.ProviderPolicy{}
	providerPolicy.AddRow(policy.ProvidersRow{Issuer: opServer.URL, ClientID: "web", ExpirationPolicy: "24h"})
	pktVerifier, err := providerPolicy.CreateVerifier(discover.DiscoveryCacheConfig{})
	require.NoError(t, err)
	verifyCmd := commands.VerifyCmd{
		PktVerifier: *pktVerifier,
		CheckPolicy: allowAnyUser,
	}
	authorizedKey, err := verifyCmd.AuthorizedKeysCommand(TestCtx, "test-user",
		pubKey.Type(), base64.StdEncoding.EncodeToString(pubKey.Marshal()), nil)
	require.NoError(t, err)
	require.Contains(t, authorizedKey, "cert-authority")
}

func allowAnyUser(string, *pktoken.PKToken, string, string, string, policy.DenyList, []string) error {
	return nil
}

func loginWithFakeOp(t *testing.T, opServer *FakeOpServer, keyPath string) {
	t.Helper()
	opkProvider, loginURL, err := opServer.OpkProvider()
	require.NoError(t, err)

	errCh := make(chan error)
	go func() {
		loginCmd := commands.LoginCmd{Fs: afero.NewOsFs(), KeyTypeArg: commands.ECDSA}
		errCh <- loginCmd.Login(TestCtx, opkProvider, false, keyPath)
	}()
	require.NoError(t, WaitForServer(TestCtx, fmt.Sprintf("%s://%s", loginURL.Scheme, loginURL.Host), LoginCallbackServerTimeout))
	DoOidcInteractiveLogin(t, nil, loginURL.String(), "test-user@localhost", "verysecure")

	timeoutCtx, cancel := context.WithTimeout(TestCtx, 3*time.Second)
	defer cancel()
	select {
	case loginErr := <-errCh:
		require.NoError(t, loginErr)
	case <-timeoutCtx.Done():
		t.Fatal(timeoutCtx.Err())
	}
}
