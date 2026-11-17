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

package policy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/opkssh/commands/discoverycache"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

// unresponsiveIssuer starts a provider that accepts connections but never
// answers, like a provider whose responses are silently dropped. It returns
// the issuer URL with the host spelled "localhost".
func unresponsiveIssuer(t *testing.T) string {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	return strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
}

func shortProviderTimeout(t *testing.T) {
	t.Helper()
	old := ProviderRequestTimeout
	ProviderRequestTimeout = 200 * time.Millisecond
	t.Cleanup(func() { ProviderRequestTimeout = old })
}

// gqTestToken returns a syntactically valid GQ256 ID token for issuer with
// the given audience and key ID. Its signature is not valid: the tests only
// need verification to reach the JWKS fetch.
func gqTestToken(t *testing.T, issuer, aud, kid string) []byte {
	t.Helper()
	enc := base64.RawURLEncoding
	origHeaders, err := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	require.NoError(t, err)
	headers, err := json.Marshal(map[string]string{"alg": "GQ256", "kid": enc.EncodeToString(origHeaders), "typ": "JWT"})
	require.NoError(t, err)
	payload, err := json.Marshal(map[string]any{
		"iss": issuer, "aud": aud, "sub": "alice", "nonce": "n",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	return []byte(enc.EncodeToString(headers) + "." + enc.EncodeToString(payload) + "." + enc.EncodeToString([]byte("sig")))
}

func TestProviderVerifierTimesOutOnUnresponsiveProvider(t *testing.T) {
	shortProviderTimeout(t)
	issuer := unresponsiveIssuer(t)

	tests := []struct {
		name string
		row  ProvidersRow
	}{
		{"google options (localhost test issuer)", ProvidersRow{Issuer: issuer, ClientID: "client", ExpirationPolicy: "24h"}},
		{"generic OIDC", ProvidersRow{Issuer: strings.Replace(issuer, "localhost", "127.0.0.1", 1), ClientID: "client", ExpirationPolicy: "24h"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pv := providerVerifierFromRow(tt.row, discover.DiscoveryCacheConfig{})
			token := gqTestToken(t, tt.row.Issuer, tt.row.ClientID, "kid-1")

			start := time.Now()
			err := pv.VerifyIDToken(context.Background(), token, &clientinstance.Claims{})
			elapsed := time.Since(start)

			require.Error(t, err)
			require.ErrorContains(t, err, "Client.Timeout")
			require.Less(t, elapsed, 5*time.Second, "verification must not wait for the TCP timeout")
		})
	}
}

func TestCachedFinderFallsBackWhenProviderIsUnresponsive(t *testing.T) {
	shortProviderTimeout(t)
	issuer := unresponsiveIssuer(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key, err := jwk.Import(rsaKey.Public())
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, "kid-1"))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(key))
	jwksJSON, err := json.Marshal(set)
	require.NoError(t, err)

	// The snapshot is 90 minutes old: too old for normal use (max_age 1h),
	// young enough for the fallback (fallback_max_age 2h).
	now := time.Now()
	written := now.Add(-90 * time.Minute)
	clock := &written
	cache := discoverycache.NewFilesystemDiscoveryCacheWithClock(func() time.Time { return *clock }, afero.NewMemMapFs(), "/cache")
	require.NoError(t, cache.Write(issuer, jwksJSON))
	clock = &now

	finder := newCachedPublicKeyFinder(discover.DiscoveryCacheConfig{
		Cache:          cache,
		StandardMaxAge: time.Hour,
		FallbackMaxAge: 2 * time.Hour,
	})

	start := time.Now()
	record, err := finder.ByKeyID(context.Background(), issuer, "kid-1", true)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.True(t, record.WasCached)
	require.Less(t, elapsed, 5*time.Second, "fallback must be reached before sshd's LoginGraceTime")
}
