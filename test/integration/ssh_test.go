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
	_ "embed"

	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openpubkey/openpubkey/discover"
	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/opkssh/commands"
	"github.com/openpubkey/opkssh/sshcert"
	testprovider "github.com/openpubkey/opkssh/test/integration/provider"
	"github.com/openpubkey/opkssh/test/integration/ssh_server"
	"github.com/spf13/afero"

	"github.com/melbahja/goph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"golang.org/x/crypto/ssh"
)

const (
	// callbackPath is the login callback path that the OIDC provider redirects
	// to after successful OIDC login
	callbackPath = "/login-callback"

	// issuerPort is the port the example OIDC provider runs its server on
	issuerPort = "9998"

	// networkName is the name of the Docker network that the test containers
	// are connected to
	networkName = "opkssh-integration-test-net"
)

//go:embed policy-plugins/plugin-simple.yml
var simplePlugin []byte

//go:embed policy-plugins/plugin-cmd.sh
var pluginCommand []byte

// oidcHttpClientTransport wraps an existing http.RoundTripper and sets the
// `Host` header of all HTTP requests to one of the registered issuer hostnames
// (oidc.local) of the dynamic zitadel example server. The zitadel server, when
// run in dynamic mode, uses the `Host` header to figure out the issuer--if we
// don't set it, then it will be 127.0.0.1 which is not the issuer that the OPK
// verifier expects
type oidcHttpClientTransport struct {
	underlyingTransport http.RoundTripper

	// port is the port that the zitadel example issuer server is running on
	// internally within the docker container (the exposed port)
	port string
}

func (t *oidcHttpClientTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Host = fmt.Sprintf("oidc.local:%s", t.port)
	return t.underlyingTransport.RoundTrip(req)
}

// pulseRefreshProvider wraps an existing provider.RefreshableOP, but modifies
// Refresh() to block until a pulse is received. Once Pulse() is called,
// Refresh() unblocks and the function call is forwarded to the underlying
// provider.RefreshableOP
type pulseRefreshProvider struct {
	RefreshableOP providers.RefreshableOpenIdProvider
	pulseCh       chan struct{}
}

// newPulseRefreshProvider creates a new pulseRefreshProvider
func newPulseRefreshProvider(provider providers.RefreshableOpenIdProvider) *pulseRefreshProvider {
	return &pulseRefreshProvider{
		RefreshableOP: provider,
		pulseCh:       make(chan struct{}, 1),
	}
}

func (p *pulseRefreshProvider) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*simpleoidc.Tokens, error) {
	return p.RefreshableOP.RequestTokens(ctx, cic)
}

func (p *pulseRefreshProvider) VerifyRefreshedIDToken(ctx context.Context, origIdt []byte, reIdt []byte) error {
	return p.RefreshableOP.VerifyRefreshedIDToken(ctx, origIdt, reIdt)
}

func (p *pulseRefreshProvider) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return p.RefreshableOP.PublicKeyByToken(ctx, token)
}

func (p *pulseRefreshProvider) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	return p.RefreshableOP.VerifyIDToken(ctx, idt, cic)
}

// Pulse unblocks Refresh()
func (p *pulseRefreshProvider) Pulse() {
	p.pulseCh <- struct{}{}
}

func (p *pulseRefreshProvider) Issuer() string {
	return p.RefreshableOP.Issuer()
}

func (p *pulseRefreshProvider) PublicKeyByKeyId(ctx context.Context, keyId string) (*discover.PublicKeyRecord, error) {
	return p.RefreshableOP.PublicKeyByKeyId(ctx, keyId)
}

// Refresh calls the underlying provider.RefreshableOP() function only after a
// pulse has been received. This function stops waiting for a pulse if TestCtx
// has been cancelled.
func (p *pulseRefreshProvider) RefreshTokens(ctx context.Context, refreshToken []byte) (*simpleoidc.Tokens, error) {
	select {
	case <-p.pulseCh:
		return p.RefreshableOP.RefreshTokens(ctx, refreshToken)
	case <-TestCtx.Done():
		return nil, TestCtx.Err()
	}
}

// createOpkSshSigner creates an ssh.Signer, for use in a go ssh client, by
// combining the OPK SSH public key (certificate) and the corresponding SSH
// private key
//
// This function returns both an ssh.Signer and the pubKey casted as an
// *ssh.Certificate
func createOpkSshSigner(t *testing.T, pubKey ssh.PublicKey, secKeyFilePath string) (ssh.Signer, *ssh.Certificate) {
	// Source: https://carlosbecker.com/posts/golang-ssh-client-certificates/

	// Parse the user's private key
	pvtKeyBts, err := os.ReadFile(secKeyFilePath)
	require.NoError(t, err)
	signer, err := ssh.ParsePrivateKey(pvtKeyBts)
	require.NoError(t, err)

	// Create a signer using both the certificate and the private key
	sshCert, ok := pubKey.(*ssh.Certificate)
	require.True(t, ok, "SSH public key should be of type *ssh.Certificate")
	certSigner, err := ssh.NewCertSigner(sshCert, signer)
	require.NoError(t, err)

	return certSigner, sshCert
}

// createZitadelOPKSshProvider creates an OPK SSH provider, the same one used by
// opkssh, except the issuer has been configured to be the fake OIDC server
// running in a Docker container
//
// This function returns both an OPK SSH provider and an HTTP transport that has
// been modified from the http.DefaultTransport to send requests to 127.0.0.1
// instead of oidc.local
func createZitadelOPKSshProvider(oidcContainerMappedPort int, authCallbackServerRedirectPort int) (zitadelOp providers.RefreshableOpenIdProvider, httpTransport http.RoundTripper) {
	// Create custom HTTP client that sends HTTP requests to the correct port
	// and valid IP of the container running the OIDC server instead of
	// "oidc.local" (which is an unknown name on the host machine); "oidc.local"
	// is still preserved in the HTTP request because we add that back in the
	// Host header
	customDialTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			// Perform "fake" DNS lookup and overwrite the outgoing
			// address--instead of sending the request to "oidc.local" (which is
			// not mapped in /etc/hosts on the host machine and therefore should
			// fail on lookup), send it to localhost and the forwarded port of
			// the OIDC container
			if addr == fmt.Sprintf("oidc.local:%s", issuerPort) {
				addr = fmt.Sprintf("127.0.0.1:%v", oidcContainerMappedPort)
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	httpTransport = &oidcHttpClientTransport{underlyingTransport: customDialTransport, port: issuerPort}
	httpClient := http.Client{Transport: httpTransport}

	zitadelOp = providers.NewGoogleOpWithOptions(&providers.GoogleOptions{
		Issuer:       fmt.Sprintf("http://oidc.local:%s/", issuerPort),
		ClientID:     "web",
		ClientSecret: "secret",
		RedirectURIs: []string{fmt.Sprintf("http://localhost:%d/login-callback", authCallbackServerRedirectPort)}, // TODO: check this correct
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
		OpenBrowser:  false,
		HttpClient:   &httpClient,
	}).(providers.RefreshableOpenIdProvider)
	return
}

// spawnTestContainers spawns a container running an example OIDC issuer and a
// linux container configured with sshd and opkssh as the
// AuthorizedKeysCommand.
//
// Test cleanup functions are registered to cleanup the containers after the
// test finishes.
func spawnTestContainers(t *testing.T) (oidcContainer *testprovider.ExampleOpContainer, authCallbackRedirectPort int, serverContainer *ssh_server.SshServerContainer) {
	// Create local Docker network so that the example OIDC container and the
	// linux container (with SSH) can communicate with each other
	newNetwork, err := testcontainers.GenericNetwork(TestCtx, testcontainers.GenericNetworkRequest{
		NetworkRequest: testcontainers.NetworkRequest{
			Name:           networkName,
			CheckDuplicate: true,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, newNetwork.Remove(TestCtx), "failed to terminate Docker network used for e2e ssh tests")
	})

	// Start OIDC server
	authCallbackRedirectPort, err = GetAvailablePort()
	require.NoError(t, err)
	oidcContainer, err = testprovider.RunExampleOpContainer(
		TestCtx,
		networkName,
		map[string]string{
			"AUTH_CALLBACK_PATH": callbackPath,
			"REDIRECT_PORT":      strconv.Itoa(authCallbackRedirectPort),
			"PORT":               issuerPort,
		},
		issuerPort,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		t.Log("Terminating OIDC container")
		require.NoError(t, oidcContainer.Terminate(TestCtx, testcontainers.StopTimeout(time.Millisecond)), "failed to terminate OIDC container")
	})

	// Track OIDC server logs and dump if test fails
	tlc := NewTestLogConsumer()
	oidcContainer.FollowOutput(tlc)
	err = oidcContainer.StartLogProducer(TestCtx)
	require.NoError(t, err)
	t.Cleanup(func() {
		if t.Failed() {
			logs := tlc.Dump()
			t.Logf("oidcContainer logs: \n%v", string(logs))
		}
	})

	// Start linux container with opkssh installed and configured to verify
	// incoming PK tokens against the OIDC issuer created above
	issuerIp, err := oidcContainer.ContainerIP(TestCtx)
	require.NoError(t, err)
	serverContainer, err = ssh_server.RunOpkSshContainer(
		TestCtx,
		issuerIp,
		issuerPort,
		networkName,
		true,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		t.Log("Terminating SSH container")
		require.NoError(t, serverContainer.Terminate(TestCtx, testcontainers.StopTimeout(time.Millisecond)), "failed to terminate SSH container")
	})

	// Use backdoor (non-OPK) SSH client to dump opkssh logs if test fails
	auth := goph.Password(serverContainer.Password)
	nonOpkSshClient, err := goph.NewConn(&goph.Config{
		User:     serverContainer.User,
		Addr:     serverContainer.Host,
		Port:     uint(serverContainer.Port),
		Auth:     auth,
		Timeout:  goph.DefaultTimeout,
		Callback: ssh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if t.Failed() {
			// Get opkssh error logs
			_, err := nonOpkSshClient.Run("sudo chmod 777 /var/log/opkssh.log")
			if assert.NoError(t, err) {
				errorLog, err := nonOpkSshClient.Run("cat /var/log/opkssh.log")
				if assert.NoError(t, err) {
					t.Logf("/var/log/opkssh.log: \n%v", string(errorLog))
				}
			}
		}
		require.NoError(t, nonOpkSshClient.Close(), "failed to close backdoor (non-OPK) SSH client")
	})
	return
}

func TestEndToEndSSH(t *testing.T) {
	// Test opkssh e2e by performing an SSH connection to a linux container.
	//
	// Tests login, policy, and verify against an example OIDC server and
	// container configured with opkssh in the "AuthorizedKeysCommand"
	var err error

	// Spawn test containers to run these tests
	oidcContainer, authCallbackRedirectPort, serverContainer := spawnTestContainers(t)
	// Create OPK SSH provider that is configured against the spawned OIDC
	// container's issuer server
	zitadelOp, customTransport := createZitadelOPKSshProvider(oidcContainer.Port, authCallbackRedirectPort)

	// Call login
	errCh := make(chan error)
	t.Log("------- call login cmd ------")
	go func() {
		loginCmd := commands.LoginCmd{Fs: afero.NewOsFs()}
		err := loginCmd.Login(TestCtx, zitadelOp, false, "")
		errCh <- err
	}()

	// Wait for login-callback server on localhost to come up. It should come up
	// when login command is called
	timeoutErr := WaitForServer(TestCtx, fmt.Sprintf("http://localhost:%d", authCallbackRedirectPort), LoginCallbackServerTimeout)
	require.NoError(t, timeoutErr, "login callback server took too long to startup")

	// Do OIDC login. Use custom transport that adds the expected Host
	// header--if not specified, then the zitadel server will say it is an
	// unexpected issuer
	DoOidcInteractiveLogin(t, customTransport, fmt.Sprintf("http://localhost:%d/login", authCallbackRedirectPort), "test-user@oidc.local", "verysecure")

	// Wait for interactive login to complete and assert no error occurred
	timeoutCtx, cancel := context.WithTimeout(TestCtx, 3*time.Second)
	defer cancel()
	select {
	case loginErr := <-errCh:
		require.NoError(t, loginErr, "failed login")
	case <-timeoutCtx.Done():
		t.Fatal(timeoutCtx.Err())
	}

	// Expect to find OPK SSH key is written to disk
	pubKey, secKeyFilePath, err := GetOPKSshKey("")
	require.NoError(t, err, "expected to find OPK ssh key written to disk")

	pubkeyBytes := base64.StdEncoding.EncodeToString(pubKey.Marshal())
	certSmug, err := sshcert.NewFromAuthorizedKey("cert-type", string(pubkeyBytes))
	require.NoError(t, err)
	accToken := certSmug.GetAccessToken()
	require.Empty(t, accToken, "expected access token to be empty since we did not request adding access token to SSH cert")

	// Create OPK SSH signer using the found OPK SSH key on disk
	certSigner, _ := createOpkSshSigner(t, pubKey, secKeyFilePath)

	// Start new ssh connection using the OPK ssh cert key
	authKey := goph.Auth{ssh.PublicKeys(certSigner)}
	opkSshClient, err := goph.NewConn(&goph.Config{
		User:     serverContainer.User,
		Addr:     serverContainer.Host,
		Port:     uint(serverContainer.Port),
		Auth:     authKey,
		Timeout:  goph.DefaultTimeout,
		Callback: ssh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)
	defer opkSshClient.Close()

	// Run simple command to test the connection
	out, err := opkSshClient.Run("whoami")
	require.NoError(t, err)
	require.Equal(t, serverContainer.User, strings.TrimSpace(string(out)))

	t.Log("Testing SFTP")
	// Ensure the test file does not exist
	remoteTestFilePath := "/home/test/testfile.txt"
	localTestFilePath := "testfile.txt"

	_, err = opkSshClient.Run("test -f " + remoteTestFilePath)
	require.Error(t, err, "expected test file to not exist")

	testContent := "IF YOU CAN READ THIS SFTP WORKS!"
	_, err = exec.Command("bash", "-c", fmt.Sprintf("echo %q > %s", testContent, localTestFilePath)).CombinedOutput()
	require.NoError(t, err, "failed to create test file")

	// Execute the SFTP command to copy the test file to the server
	sftpCommand := fmt.Sprintf("echo 'put %s %s' | sftp -o StrictHostKeyChecking=no -P %d %s@%s",
		localTestFilePath, remoteTestFilePath, uint(serverContainer.Port), serverContainer.User, serverContainer.Host)
	out, err = exec.Command("bash", "-c", sftpCommand).CombinedOutput()
	require.NoError(t, err, "failed to execute SFTP command")

	out, err = opkSshClient.Run("cat " + remoteTestFilePath)
	require.NoError(t, err)
	require.Equal(t, testContent, strings.TrimSpace(string(out)), "SFTP file content mismatch")
}

func TestEndToEndSSHUserInfo(t *testing.T) {
	// Test opkssh e2e  (with userinfo) by performing an SSH connection to a linux container.
	//
	// Tests login, policy, and verify against an example OIDC server and
	// container configured with opkssh in the "AuthorizedKeysCommand"
	// Currently the test OP doesn't give us any userinfo that isn't in the ID token.
	// Thus, the policy check does not use the userinfo information.
	// TODO: Improve this test so include a policy check that depends on userinfo claims.
	var err error

	// Spawn test containers to run these tests
	oidcContainer, authCallbackRedirectPort, serverContainer := spawnTestContainers(t)
	// Create OPK SSH provider that is configured against the spawned OIDC
	// container's issuer server
	zitadelOp, customTransport := createZitadelOPKSshProvider(oidcContainer.Port, authCallbackRedirectPort)

	// Call login
	errCh := make(chan error)
	t.Log("------- call login cmd ------")
	go func() {
		loginCmd := commands.LoginCmd{
			Fs:                 afero.NewOsFs(),
			SendAccessTokenArg: true,
			Verbosity:          2,
		}
		err := loginCmd.Login(TestCtx, zitadelOp, false, "")
		errCh <- err
	}()

	// Wait for login-callback server on localhost to come up. It should come up
	// when login command is called
	timeoutErr := WaitForServer(TestCtx, fmt.Sprintf("http://localhost:%d", authCallbackRedirectPort), LoginCallbackServerTimeout)
	require.NoError(t, timeoutErr, "login callback server took too long to startup")

	// Do OIDC login. Use custom transport that adds the expected Host
	// header--if not specified, then the zitadel server will say it is an
	// unexpected issuer
	DoOidcInteractiveLogin(t, customTransport, fmt.Sprintf("http://localhost:%d/login", authCallbackRedirectPort), "test-user@oidc.local", "verysecure")

	// Wait for interactive login to complete and assert no error occurred
	timeoutCtx, cancel := context.WithTimeout(TestCtx, 3*time.Second)
	defer cancel()
	select {
	case loginErr := <-errCh:
		require.NoError(t, loginErr, "failed login")
	case <-timeoutCtx.Done():
		t.Fatal(timeoutCtx.Err())
	}

	// Expect to find OPK SSH key is written to disk
	pubKey, secKeyFilePath, err := GetOPKSshKey("")
	require.NoError(t, err, "expected to find OPK ssh key written to disk")
	pubkeyBytes := base64.StdEncoding.EncodeToString(pubKey.Marshal())
	certSmug, err := sshcert.NewFromAuthorizedKey("cert-type", string(pubkeyBytes))
	require.NoError(t, err)
	accToken := certSmug.GetAccessToken()
	require.NotEmpty(t, accToken, "expected access token to not be since we requested access token on SSH cert")

	// Create OPK SSH signer using the found OPK SSH key on disk
	certSigner, _ := createOpkSshSigner(t, pubKey, secKeyFilePath)

	// Start new ssh connection using the OPK ssh cert key
	authKey := goph.Auth{ssh.PublicKeys(certSigner)}

	opkSshClient, err := goph.NewConn(&goph.Config{
		User:     serverContainer.User,
		Addr:     serverContainer.Host,
		Port:     uint(serverContainer.Port),
		Auth:     authKey,
		Timeout:  goph.DefaultTimeout,
		Callback: ssh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)
	defer opkSshClient.Close()

	// Run simple command to test the connection
	out, err := opkSshClient.Run("whoami")
	require.NoError(t, err)
	require.Equal(t, serverContainer.User, strings.TrimSpace(string(out)))
}

func TestEndToEndSSHAsUnprivilegedUser(t *testing.T) {
	// Test usecase of unprivileged user using opkssh e2e by performing an SSH
	// connection to a linux container.
	//
	// This user has policy access via their user policy--not the root policy
	var err error

	// Spawn test containers to run these tests
	oidcContainer, authCallbackRedirectPort, serverContainer := spawnTestContainers(t)
	// Create OPK SSH provider that is configured against the spawned OIDC
	// container's issuer server
	zitadelOp, customTransport := createZitadelOPKSshProvider(oidcContainer.Port, authCallbackRedirectPort)

	// Give integration test user access to test2 via user policy
	issuer := fmt.Sprintf("http://oidc.local:%s/", issuerPort)
	cmdString := fmt.Sprintf("opkssh add \"test2\" \"test-user@zitadel.ch\" \"%s\"", issuer)
	code, _ := executeCommandAsUser(t, serverContainer.Container, []string{"/bin/bash", "-c", cmdString}, "test2")
	require.Equal(t, 0, code, "failed to update user policy")

	// Call login
	errCh := make(chan error)
	t.Log("------- call login cmd ------")
	go func() {
		loginCmd := commands.LoginCmd{Fs: afero.NewOsFs()}
		err := loginCmd.Login(TestCtx, zitadelOp, false, "")
		errCh <- err
	}()

	// Wait for login-callback server on localhost to come up. It should come up
	// when login command is called
	timeoutErr := WaitForServer(TestCtx, fmt.Sprintf("http://localhost:%d", authCallbackRedirectPort), LoginCallbackServerTimeout)
	require.NoError(t, timeoutErr, "login callback server took too long to startup")

	// Do OIDC login. Use custom transport that adds the expected Host
	// header--if not specified, then the zitadel server will say it is an
	// unexpected issuer
	DoOidcInteractiveLogin(t, customTransport, fmt.Sprintf("http://localhost:%d/login", authCallbackRedirectPort), "test-user@oidc.local", "verysecure")

	// Wait for interactive login to complete and assert no error occurred
	timeoutCtx, cancel := context.WithTimeout(TestCtx, 3*time.Second)
	defer cancel()
	select {
	case loginErr := <-errCh:
		require.NoError(t, loginErr, "failed login")
	case <-timeoutCtx.Done():
		t.Fatal(timeoutCtx.Err())
	}

	// Expect to find OPK SSH key is written to disk
	pubKey, secKeyFilePath, err := GetOPKSshKey("")
	require.NoError(t, err, "expected to find OPK ssh key written to disk")

	// Create OPK SSH signer using the found OPK SSH key on disk
	certSigner, _ := createOpkSshSigner(t, pubKey, secKeyFilePath)

	// Start new ssh connection using the OPK ssh cert key
	authKey := goph.Auth{ssh.PublicKeys(certSigner)}
	opkSshClient, err := goph.NewConn(&goph.Config{
		User:     "test2", // test2 is not a sudoer
		Addr:     serverContainer.Host,
		Port:     uint(serverContainer.Port),
		Auth:     authKey,
		Timeout:  goph.DefaultTimeout,
		Callback: ssh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)
	defer opkSshClient.Close()

	// Run simple command to test the connection
	out, err := opkSshClient.Run("whoami")
	require.NoError(t, err)
	require.Equal(t, "test2", strings.TrimSpace(string(out)))
}

func updateIdTokenLifetime(t *testing.T, oidcContainerMappedPort int, duration string) {
	controlServerClient := &http.Client{}
	controlWebClientBaseURL := fmt.Sprintf("http://127.0.0.1:%d/control/client/web/", oidcContainerMappedPort) + "%s"
	req, err := http.NewRequestWithContext(TestCtx, http.MethodPatch, fmt.Sprintf(controlWebClientBaseURL, "idTokenLifetime"), bytes.NewBufferString(duration))
	require.NoError(t, err)
	resp, err := controlServerClient.Do(req)
	require.NoError(t, err, "PATCH idTokenLifetime")
	defer resp.Body.Close()
	defer func() {
		if t.Failed() {
			body, _ := io.ReadAll(resp.Body)
			t.Logf("PATCH idTokenLifetime: body: %s", string(body))
		}
	}()
	require.Equal(t, 200, resp.StatusCode)
}

func TestEndToEndSSHWithRefresh(t *testing.T) {
	// Test refresh flow of opkssh e2e by first attempting to SSH with an
	// expired id_token (and expect a failure). Then, let the background refresh
	// process get a new unexpired id_token, and then attempt a successful SSH
	// connection.
	//
	// The second SSH connection should succeed as the verifier on the container
	// should see an unexpired, valid refreshed_id_token in the PKT header.
	var err error

	// Spawn test containers to run these tests
	oidcContainer, authCallbackRedirectPort, serverContainer := spawnTestContainers(t)
	// Create OPK SSH provider that is configured against the spawned OIDC
	// container's issuer server
	zitadelOp, customTransport := createZitadelOPKSshProvider(oidcContainer.Port, authCallbackRedirectPort)

	// Control when this provider is permitted to call refresh logic with the
	// OP. We need fine control over refresh since this test modifies the OIDC
	// issuer server's id_token expiration time on the fly. We don't want
	// refresh to run until the expiration time has successfully been changed
	pulseZitadelOp := newPulseRefreshProvider(zitadelOp)

	// Create error channel to hold any errors that can occur during login or
	// the background refresh process
	errCh := make(chan error, 1)
	// If the test fails, check to see if there is an error on this channel as
	// it may give information on why the overall test has failed
	t.Cleanup(func() {
		// Drain errCh. Check to see if there is an important error
		select {
		case err := <-errCh:
			if errors.Is(err, context.Canceled) {
				return
			}
			require.NoError(t, err, "LoginWithRefresh process returned an unexpected error")
		default:
			// LoginWithRefresh returned no errors
		}
	})

	// Call login with refresh enabled. Must spawn on goroutine because refresh
	// runs forever until context is cancelled or an error occurs.
	refreshCtx, cancelRefresh := context.WithCancel(TestCtx)
	defer cancelRefresh()
	t.Log("------- call login cmd ------")
	go func() {
		loginCmd := commands.LoginCmd{Fs: afero.NewOsFs()}
		err := loginCmd.LoginWithRefresh(refreshCtx, pulseZitadelOp, false, "")
		errCh <- err
	}()

	// Wait for login-callback server on localhost to come up. It should come up
	// when login command is called
	timeoutErr := WaitForServer(TestCtx, fmt.Sprintf("http://localhost:%d", authCallbackRedirectPort), LoginCallbackServerTimeout)
	require.NoError(t, timeoutErr, "login callback server took too long to startup")

	// Update idTokenLifetime to 10s. Can't make this too small otherwise code
	// exchange fails completely (i.e we need enough time to complete the whole
	// interactive OIDC login flow)
	updateIdTokenLifetime(t, oidcContainer.Port, "10s")

	// Do OIDC login. Use custom transport that adds the expected Host
	// header--if not specified, then the zitadel server will say it is an
	// unexpected issuer
	DoOidcInteractiveLogin(t, customTransport, fmt.Sprintf("http://localhost:%d/login", authCallbackRedirectPort), "test-user@oidc.local", "verysecure")

	// findOPKSshKeyTimeout is how long to wait for an OPK SSH key to be written
	// to disk
	const findOPKSshKeyTimeout = 5 * time.Second

	// Expect to find OPK SSH key is written to disk.
	//
	// Notice: Unlike the non-refresh SSH test, we must run this assertion many
	// times until we see what we want (or timeout); we can't immediately run
	// this check like before because there isn't a mechanism to know when login
	// process has finished and refresh background process has begun
	var pubKey ssh.PublicKey
	var secKeyFilePath string
	findKeyCtx, findKeyCancel := context.WithTimeout(TestCtx, findOPKSshKeyTimeout)
	defer findKeyCancel()
	t.Logf("Waiting for login process to write an OPK ssh key to disk...")
	err = TryFunc(findKeyCtx, func() error {
		pubKey, secKeyFilePath, err = GetOPKSshKey("")
		return err
	})
	require.NoError(t, err, "expected to find OPK ssh key written to disk")

	// Create OPK SSH signer using the found OPK SSH key on disk
	certSigner, sshCert := createOpkSshSigner(t, pubKey, secKeyFilePath)

	// Wait for id_token to expire (should not take longer than 10 seconds)
	pktCom, ok := sshCert.Extensions["openpubkey-pkt"]
	require.True(t, ok, "expected to find openpubkey-pkt extension")
	pkt, err := pktoken.NewFromCompact([]byte(pktCom))
	require.NoError(t, err)
	var claims struct {
		Expiration int64 `json:"exp"`
	}
	err = json.Unmarshal(pkt.Payload, &claims)

	require.NoError(t, err)
	expTime := time.Unix(claims.Expiration, 0)
	untilExpired := time.Until(expTime)
	t.Logf("Waiting for id token to expire before making first OPK SSH connection: %v...", untilExpired)
	select {
	case <-time.After(untilExpired):
		t.Log("sshing...")
	case <-TestCtx.Done():
		t.Fatal(TestCtx.Err())
	}

	// Start new ssh connection using the OPK ssh cert key
	authKey := goph.Auth{ssh.PublicKeys(certSigner)}
	opkSshClient, err := goph.NewConn(&goph.Config{
		User:     serverContainer.User,
		Addr:     serverContainer.Host,
		Port:     uint(serverContainer.Port),
		Auth:     authKey,
		Timeout:  goph.DefaultTimeout,
		Callback: ssh.InsecureIgnoreHostKey(),
	})
	require.Error(t, err, "OPK SSH connection should not be successful since id_token should be expired")

	// Reset idTokenLifetime to 1 hour, so that the refreshed id_token doesn't
	// expire before this test completes
	updateIdTokenLifetime(t, oidcContainer.Port, "1h")

	// Delete expired SSH key, so we can find a new OPK SSH key after running
	// refresh; otherwise, we might read the stale key before refresh finishes
	//
	// TODO-Yuval: Ideally, we should change Login() to take in custom SSH
	// directory path so we're not touching the host machine's SSH keys
	err = os.Remove(secKeyFilePath)
	require.NoError(t, err, "failed to remove OPK SSH private key")
	err = os.Remove(secKeyFilePath + ".pub")
	require.NoError(t, err, "failed to remove OPK SSH public key")

	// Let refresh go through
	pulseZitadelOp.Pulse()

	// Expect to find OPK SSH key is written to disk
	findRefreshedKeyCtx, findRefreshedKeyCancel := context.WithTimeout(TestCtx, findOPKSshKeyTimeout)
	defer findRefreshedKeyCancel()
	t.Logf("Waiting for refresh process to write an OPK ssh key to disk...")
	err = TryFunc(findRefreshedKeyCtx, func() error {
		pubKey, secKeyFilePath, err = GetOPKSshKey("")
		return err
	})
	require.NoError(t, err, "expected to find OPK ssh key written to disk after refresh")

	// Create OPK SSH signer using the refreshed OPK SSH key on disk
	certSigner, _ = createOpkSshSigner(t, pubKey, secKeyFilePath)

	// Start new ssh connection using the refreshed OPK ssh cert key
	authKey = goph.Auth{ssh.PublicKeys(certSigner)}
	opkSshClient, err = goph.NewConn(&goph.Config{
		User:     serverContainer.User,
		Addr:     serverContainer.Host,
		Port:     uint(serverContainer.Port),
		Auth:     authKey,
		Timeout:  goph.DefaultTimeout,
		Callback: ssh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err, "expected to be able to SSH after refreshing id_token")
	defer opkSshClient.Close()

	// Run simple command to test the connection
	out, err := opkSshClient.Run("whoami")
	require.NoError(t, err)
	require.Equal(t, serverContainer.User, strings.TrimSpace(string(out)))
}

func TestSSHPolicyPlugin(t *testing.T) {
	// Test policy plugin system e2e by performing an SSH connection to a linux container.
	//
	// Tests login, policy, and verify against an example OIDC server and
	// container configured with opkssh in the "AuthorizedKeysCommand"
	var err error

	// Spawn test containers to run these tests
	oidcContainer, authCallbackRedirectPort, serverContainer := spawnTestContainers(t)

	// We set the oidc user to "test-user2" (email: "test-user2@zitadel.ch") which is not in the auth_id
	// but is in our test policy plugin.
	authKey := OpksshLoginAs(t, "test-user2", "pluginkey", oidcContainer, authCallbackRedirectPort)
	// authKey := OpksshLoginAs(t, "test-user@oidc.local", "pluginkey", oidcContainer, authCallbackRedirectPort)

	opkSshClientSuccess, err := goph.NewConn(&goph.Config{
		User:     "root",
		Addr:     serverContainer.Host,
		Port:     uint(serverContainer.Port),
		Auth:     authKey,
		Timeout:  goph.DefaultTimeout,
		Callback: ssh.InsecureIgnoreHostKey(),
	})
	require.Error(t, err, "OPK SSH connection fail since we haven't added the policy plugin yet")

	// CreatePolicyPlugin(t, echoAllowPlugin, serverContainer)
	CreatePolicyPlugin(t, simplePlugin, pluginCommand, serverContainer)

	opkSshClientSuccess, err = goph.NewConn(&goph.Config{
		User:     "root",
		Addr:     serverContainer.Host,
		Port:     uint(serverContainer.Port),
		Auth:     authKey,
		Timeout:  goph.DefaultTimeout,
		Callback: ssh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)
	defer opkSshClientSuccess.Close()

	// Run simple command to test the connection
	out, err := opkSshClientSuccess.Run("whoami")
	require.NoError(t, err)
	require.Equal(t, "root", strings.TrimSpace(string(out)))
}

func CreatePolicyPlugin(t *testing.T, pluginConfig []byte, pluginCmd []byte, serverContainer *ssh_server.SshServerContainer) {
	// Use backdoor (non-OPK) SSH client to dump opkssh logs if test fails
	auth := goph.Password(serverContainer.Password)
	nonOpkSshClient, err := goph.NewConn(&goph.Config{
		User:     serverContainer.User,
		Addr:     serverContainer.Host,
		Port:     uint(serverContainer.Port),
		Auth:     auth,
		Timeout:  goph.DefaultTimeout,
		Callback: ssh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)

	writePluginConfig := fmt.Sprintf(`sudo tee /etc/opk/policy.d/test-plugin.yml << 'EOF'
%s
EOF`, string(pluginConfig))

	_, err = nonOpkSshClient.Run(writePluginConfig)
	require.NoError(t, err, "writing policy plugin config")

	// now fix perms/ownership
	_, err = nonOpkSshClient.Run("sudo chmod 640 /etc/opk/policy.d/test-plugin.yml")
	require.NoError(t, err, "chmod policy plugin config")

	_, err = nonOpkSshClient.Run("sudo chown root:opksshuser /etc/opk/policy.d/test-plugin.yml")
	require.NoError(t, err, "chown policy plugin config")

	writePluginCmd := fmt.Sprintf(`sudo tee /tmp/plugin-cmd.sh << 'EOF'
%s
EOF`, string(pluginCmd))

	_, err = nonOpkSshClient.Run(writePluginCmd)
	require.NoError(t, err, "writing policy plugin command")

	// now fix perms/ownership
	_, err = nonOpkSshClient.Run("sudo chmod 755 /tmp/plugin-cmd.sh")
	require.NoError(t, err, "chmod policy plugin command")

	_, err = nonOpkSshClient.Run("sudo chown root:opksshuser /tmp/plugin-cmd.sh")
	require.NoError(t, err, "chown policy plugin command")

	require.NoError(t, nonOpkSshClient.Close(), "failed to close test setup (non-OPK) SSH client")
}

func OpksshLoginAs(t *testing.T, oidcUser string, keyName string,
	oidcContainer *testprovider.ExampleOpContainer, authCallbackRedirectPort int) goph.Auth {
	// Create OPK SSH provider that is configured against the spawned OIDC
	// container's issuer server
	zitadelOp, customTransport := createZitadelOPKSshProvider(oidcContainer.Port, authCallbackRedirectPort)

	homePath, err := os.UserHomeDir()
	require.NoError(t, err)
	sshPath := filepath.Join(homePath, ".ssh")

	// Make ~/.ssh if folder does not exist
	err = os.MkdirAll(sshPath, os.ModePerm)
	require.NoError(t, err)
	seckeyPath := filepath.Join(sshPath, keyName)

	// Call login
	errCh := make(chan error)
	t.Log("------- call login cmd ------")
	go func() {
		loginCmd := commands.LoginCmd{Fs: afero.NewOsFs()}
		err := loginCmd.Login(TestCtx, zitadelOp, false, seckeyPath)
		errCh <- err
	}()

	// Wait for login-callback server on localhost to come up. It should come up
	// when login command is called
	timeoutErr := WaitForServer(TestCtx, fmt.Sprintf("http://localhost:%d", authCallbackRedirectPort), LoginCallbackServerTimeout)
	require.NoError(t, timeoutErr, "login callback server took too long to startup")

	// Do OIDC login. Use custom transport that adds the expected Host
	// header--if not specified, then the zitadel server will say it is an
	// unexpected issuer
	DoOidcInteractiveLogin(t, customTransport, fmt.Sprintf("http://localhost:%d/login", authCallbackRedirectPort), oidcUser, "verysecure")

	// Wait for interactive login to complete and assert no error occurred
	timeoutCtx, cancel := context.WithTimeout(TestCtx, 3*time.Second)
	defer cancel()
	select {
	case loginErr := <-errCh:
		require.NoError(t, loginErr, "failed login")
	case <-timeoutCtx.Done():
		t.Fatal(timeoutCtx.Err())
	}

	// Expect to find OPK SSH key is written to disk
	pubKey, secKeyFilePath, err := GetOPKSshKey(seckeyPath)
	require.NoError(t, err, "expected to find OPK ssh key written to disk at %s", seckeyPath)

	// Create OPK SSH signer using the found OPK SSH key on disk
	certSigner, _ := createOpkSshSigner(t, pubKey, secKeyFilePath)

	// Return key that can be used to SSH into the server container
	return goph.Auth{ssh.PublicKeys(certSigner)}
}
