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

//go:build integration

package integration

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"log/slog"

	"github.com/jeremija/gosubmit"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/example/server/exampleop"
	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// FakeOpServer is an OIDC provider example server that runs on a system-chosen
// port on the local loopback interface for use in e2e tests.
type FakeOpServer struct {
	op.Storage
	*httptest.Server
}

type deferredHandler struct {
	http.Handler
}

// NewFakeOpServer starts and returns a new FakeOpServer. The caller should call
// Close() when finished to shut it down.
func NewFakeOpServer() (*FakeOpServer, error) {
	exampleStorage := storage.NewStorage(storage.NewUserStore("http://localhost"))

	// Start new HTTP server
	var dh deferredHandler
	opServer := httptest.NewServer(&dh)
	issuerUrl := opServer.URL
	serverLogger := slog.New(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: true,
			Level:     slog.LevelDebug,
		}),
	)

	// Create the OIDC server handler and set this as the test HTTP server's
	// handler
	opRouter := exampleop.SetupServer(issuerUrl, exampleStorage, serverLogger, false)
	dh.Handler = opRouter

	return &FakeOpServer{
		Storage: exampleStorage,
		Server:  opServer,
	}, nil
}

// OpkProvider returns an OPK provider configured to interact with this fake
// OIDC server and the login URL that is served by this OPK provider on
// localhost when requesting tokens from the OP.
//
// The OPK provider uses this server's registered web client application's auth
// details (clientID + clientSecret). scopes are the scopes to request when
// performing OIDC login flow; if empty, then default scopes are used.
func (s *FakeOpServer) OpkProvider() (providers.OpenIdProvider, *url.URL, error) {
	// Find available port to run local auth callback server on when requesting
	// tokens from the OP.
	//
	// Technically, there is a small chance that this port is no longer free
	// before Login() is called. But we need to register the accepted redirect
	// URIs with the exampleop server before performing login.
	redirectURIPort, err := GetAvailablePort()
	if err != nil {
		return nil, nil, err
	}

	// Login callback path to redirect to after successful OIDC login
	callbackPath := "/login-callback"
	redirectURI := fmt.Sprintf("http://localhost:%d%s", redirectURIPort, callbackPath)

	// Register some OIDC client applications with this example OIDC server
	nativeClient := storage.NativeClient("native", redirectURI)
	clientSecret := "secret"
	webClient := storage.WebClient("web", clientSecret, redirectURI)
	storage.RegisterClients(
		nativeClient,
		webClient,
	)

	// The *provider.GoogleProvider provider hosts the Op login redirect URL at
	// /login
	loginURL, err := url.Parse(fmt.Sprintf("http://localhost:%d/login", redirectURIPort))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create login URL: %w", err)
	}

	// Disable auto-open URL feature as this provider should be used in
	// automated tests and not require user interaction via the browser
	provider := providers.NewGoogleOpWithOptions(
		&providers.GoogleOptions{
			Issuer:       s.URL,
			ClientID:     webClient.GetID(),
			ClientSecret: clientSecret,
			RedirectURIs: []string{fmt.Sprintf("http://localhost:%d/login-callback", redirectURIPort)},
			Scopes:       []string{"openid", "profile", "email", "offline_access"},
			OpenBrowser:  false,
		},
	)

	return provider, loginURL, nil
}

// DoOidcInteractiveLogin runs the OIDC login procedure e2e from auth callback
// server <--> OP login, assuming the OP server is running the zitadel exampleop
// server.
//
// transport allows for customizing the Transport of the HTTP client used to
// interact with the auth callback server and OP server. If nil,
// http.DefaultTransport is used.
//
// loginURL is the auth callback server's login page that redirects to the OP
// login page. username and password are the auth details to use to login when
// presented with the login form.
//
// This function expects that the auth callback server serving loginURL is
// already running.
//
// Only call this function in a go test function that has access to *testing.T.
// If any error occurs when executing the login procedure, the test stops
// execution and is marked as a failed test.
func DoOidcInteractiveLogin(t *testing.T, transport http.RoundTripper, loginURL string, username string, password string) {
	// Source: https://github.com/zitadel/oidc/blob/9d12d1d900f30a2eed3a8e60b5e33988758409bf/pkg/client/integration_test.go#L191

	jar, err := cookiejar.New(nil)
	require.NoError(t, err, "create cookie jar")
	httpClient := &http.Client{
		Timeout: time.Second * 5,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: transport,
		Jar:       jar,
	}

	t.Log("------- get OIDC provider login page ------")
	// Find the OIDC provider's login page by performing GET on the auth
	// callback server's login URL (AuthURLHandler)
	loginPageUrl, err := url.Parse(loginURL)
	require.NoError(t, err)
	loginPageUrl = getRedirect(t, "get redirect login url (#1)", httpClient, loginPageUrl)
	t.Logf("loginPageUrl (redirect #1): %v", loginPageUrl)
	loginPageUrl = getRedirect(t, "get redirect login url (#2)", httpClient, loginPageUrl)
	t.Logf("loginPageUrl (redirect #2): %v", loginPageUrl)

	// Get login form hosted by the fake OIDC provider server
	t.Log("------- get login form ------")
	form := getForm(t, "get login form", httpClient, loginPageUrl)
	t.Logf("login form (unfilled): %s", string(form))

	// Perform login with supplied username and password
	t.Log("------- post to login form, get redirect to OP ------")
	postLoginRedirectURL := fillForm(t, "fill login form", httpClient, form, loginPageUrl,
		gosubmit.Set("username", username),
		gosubmit.Set("password", password),
	)
	t.Logf("Get redirect from %s", postLoginRedirectURL)

	t.Log("------- redirect from OP back to auth callback server ------")
	codeBearingURL := getRedirect(t, "get redirect with code", httpClient, postLoginRedirectURL)
	t.Logf("Redirect with code %s", codeBearingURL)

	t.Log("------- complete OIDC flow (follow redirect URI) ------")
	resp, err := httpClient.Get(codeBearingURL.String())
	require.NoError(t, err, "GET "+codeBearingURL.String())
	defer resp.Body.Close()
	defer func() {
		if t.Failed() {
			body, _ := io.ReadAll(resp.Body)
			t.Logf("codeBearingURL: GET %s: body: %s", codeBearingURL, string(body))
		}
	}()
	require.Equal(t, 200, resp.StatusCode)
	t.Log("Successfully completed OIDC login!")
}

func getRedirect(t *testing.T, desc string, httpClient *http.Client, uri *url.URL) *url.URL {
	// Source: https://github.com/zitadel/oidc/blob/9d12d1d900f30a2eed3a8e60b5e33988758409bf/pkg/client/integration_test.go#L442

	req := &http.Request{
		Method: "GET",
		URL:    uri,
		Header: make(http.Header),
	}
	resp, err := httpClient.Do(req)
	require.NoError(t, err, "GET "+uri.String())
	defer resp.Body.Close()

	defer func() {
		if t.Failed() {
			body, _ := io.ReadAll(resp.Body)
			t.Logf("%s: GET %s: body: %s", desc, uri, string(body))
		}
	}()

	redirect, err := resp.Location()
	require.NoErrorf(t, err, "%s: get redirect %s", desc, uri)
	require.NotEmptyf(t, redirect, "%s: get redirect %s", desc, uri)
	return redirect
}

func getForm(t *testing.T, desc string, httpClient *http.Client, uri *url.URL) []byte {
	// Source: https: //github.com/zitadel/oidc/blob/9d12d1d900f30a2eed3a8e60b5e33988758409bf/pkg/client/integration_test.go#L466

	req := &http.Request{
		Method: "GET",
		URL:    uri,
		Header: make(http.Header),
	}
	resp, err := httpClient.Do(req)
	require.NoErrorf(t, err, "%s: GET %s", desc, uri)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "%s: read GET %s", desc, uri)
	return body
}

func fillForm(t *testing.T, desc string, httpClient *http.Client, body []byte, uri *url.URL, opts ...gosubmit.Option) *url.URL {
	// Source: https://github.com/zitadel/oidc/blob/9d12d1d900f30a2eed3a8e60b5e33988758409bf/pkg/client/integration_test.go#L481

	req := gosubmit.ParseWithURL(io.NopCloser(bytes.NewReader(body)), uri.String()).FirstForm().Testing(t).NewTestRequest(
		append([]gosubmit.Option{gosubmit.AutoFill()}, opts...)...,
	)
	if req.URL.Scheme == "" {
		req.URL = uri
		t.Log("request lost it's proto..., adding back... request now", req.URL)
	}
	req.RequestURI = "" // bug in gosubmit?
	resp, err := httpClient.Do(req)
	require.NoErrorf(t, err, "%s: POST %s", desc, uri)

	defer resp.Body.Close()
	defer func() {
		if t.Failed() {
			body, _ := io.ReadAll(resp.Body)
			t.Logf("%s: GET %s: body: %s", desc, uri, string(body))
		}
	}()

	redirect, err := resp.Location()
	require.NoErrorf(t, err, "%s: redirect for POST %s", desc, uri)
	return redirect
}
