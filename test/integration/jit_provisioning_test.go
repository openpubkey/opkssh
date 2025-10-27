//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/melbahja/goph"
	"github.com/openpubkey/opkssh/commands"
	testprovider "github.com/openpubkey/opkssh/test/integration/provider"
	"github.com/openpubkey/opkssh/test/integration/ssh_server"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"golang.org/x/crypto/ssh"
)

// TestJITUserProvisioningEndToEnd tests the complete JIT user provisioning flow:
// 1. Start OIDC provider
// 2. Start SSH server with OPKSSH and NSS module installed
// 3. Login with OPKSSH to create SSH certificate
// 4. SSH to server as non-existent user
// 5. Verify user is created automatically
// 6. Verify SSH session is established successfully
func TestJITUserProvisioningEndToEnd(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Create local Docker network
	newNetwork, err := testcontainers.GenericNetwork(ctx, testcontainers.GenericNetworkRequest{
		NetworkRequest: testcontainers.NetworkRequest{
			Name:           "opkssh-jit-test-net",
			CheckDuplicate: true,
		},
	})
	require.NoError(t, err)
	defer func() {
		if err := newNetwork.Remove(ctx); err != nil {
			t.Logf("failed to terminate Docker network: %v", err)
		}
	}()

	// Start OIDC server
	authCallbackRedirectPort, err := GetAvailablePort()
	require.NoError(t, err)
	oidcContainer, err := testprovider.RunExampleOpContainer(
		ctx,
		"opkssh-jit-test-net",
		map[string]string{
			"REDIRECT_URIS": fmt.Sprintf("http://localhost:%d/login-callback", authCallbackRedirectPort),
			"USER_PASSWORD": "verysecure",
		},
		issuerPort,
	)
	require.NoError(t, err)
	defer func() {
		if err := oidcContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate OIDC container: %v", err)
		}
	}()

	// Start SSH server container with OPKSSH and NSS module
	// Fetch IPv4 address of OIDC container so that sshd server can route
	// traffic to it
	issuerHostIp, err := oidcContainer.ContainerIP(ctx)
	require.NoError(t, err)

	sshContainer, err := ssh_server.RunOpkSshContainer(ctx, issuerHostIp, issuerPort, "opkssh-jit-test-net", true)
	require.NoError(t, err)
	defer func() {
		if err := sshContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate SSH container: %v", err)
		}
	}()

	// Enable JIT user provisioning in the container
	exitCode, _, err := sshContainer.Exec(ctx, []string{"sh", "-c", "echo 'enabled true' > /etc/opk/nss-opkssh.conf"})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)

	exitCode, _, err = sshContainer.Exec(ctx, []string{"sh", "-c", "echo 'auto_provision_users: true' >> /etc/opk/config.yml"})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)

	// Verify NSS module is installed and configured
	exitCode, output, err := sshContainer.Exec(ctx, []string{"getent", "passwd", "nonexistentuser_jit"})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode, "getent should succeed with NSS module enabled")
	require.Contains(t, output, "nonexistentuser_jit", "NSS module should return user info")
	require.Contains(t, output, "65534", "NSS module should return UID 65534")

	// Create OPK SSH provider configured against the OIDC container
	zitadelOp, customTransport := createZitadelOPKSshProvider(oidcContainer.Port, authCallbackRedirectPort)

	// Call login to generate SSH certificate
	t.Log("------- call login cmd ------")
	errCh := make(chan error)
	go func() {
		loginCmd := commands.LoginCmd{Fs: afero.NewOsFs()}
		err := loginCmd.Login(ctx, zitadelOp, false, "")
		errCh <- err
	}()

	// Wait for login-callback server to come up
	timeoutErr := WaitForServer(ctx, fmt.Sprintf("http://localhost:%d", authCallbackRedirectPort), LoginCallbackServerTimeout)
	require.NoError(t, timeoutErr, "login callback server took too long to startup")

	// Do OIDC login
	DoOidcInteractiveLogin(t, customTransport, fmt.Sprintf("http://localhost:%d/login", authCallbackRedirectPort), "test-user@oidc.local", "verysecure")

	// Wait for interactive login to complete
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	select {
	case loginErr := <-errCh:
		require.NoError(t, loginErr, "failed login")
	case <-timeoutCtx.Done():
		t.Fatal(timeoutCtx.Err())
	}

	// Get the generated OPK SSH key
	pubKey, secKeyFilePath, err := GetOPKSshKey("")
	require.NoError(t, err, "expected to find OPK ssh key written to disk")

	// Create OPK SSH signer
	certSigner, _ := createOpkSshSigner(t, pubKey, secKeyFilePath)

	// Test username that doesn't exist on the system
	testUsername := "jituser123"

	// Verify user doesn't exist initially
	exitCode, _, err = sshContainer.Exec(ctx, []string{"id", testUsername})
	require.NoError(t, err)
	require.NotEqual(t, 0, exitCode, "user should not exist before SSH login")

	// Add policy to allow the test user to SSH as testUsername
	mockEmail := "test-user@oidc.local"
	mockIssuer := fmt.Sprintf("http://oidc.local:%s/", issuerPort)
	policyLine := fmt.Sprintf("%s %s %s", testUsername, mockEmail, mockIssuer)

	exitCode, _, err = sshContainer.Exec(ctx, []string{"sh", "-c", fmt.Sprintf("echo '%s' >> /etc/opk/auth_id", policyLine)})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)

	// Attempt SSH connection as the non-existent user
	// This should trigger JIT user provisioning
	authKey := goph.Auth{ssh.PublicKeys(certSigner)}
	sshClient, err := goph.NewConn(&goph.Config{
		User:     testUsername,
		Addr:     sshContainer.Host,
		Port:     uint(sshContainer.Port),
		Auth:     authKey,
		Callback: ssh.InsecureIgnoreHostKey(),
		Timeout:  30 * time.Second,
	})
	require.NoError(t, err, "SSH connection should succeed with JIT provisioning")
	defer sshClient.Close()

	// Verify we can execute commands
	outputBytes, err := sshClient.Run("whoami")
	require.NoError(t, err)
	require.Equal(t, testUsername, strings.TrimSpace(string(outputBytes)), "SSH session should be as the provisioned user")

	// Verify user was actually created on the system
	exitCode, output, err = sshContainer.Exec(ctx, []string{"id", testUsername})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode, "user should exist after SSH login")
	require.Contains(t, output, testUsername, "id command should return the username")

	// Verify user's home directory was created
	exitCode, _, err = sshContainer.Exec(ctx, []string{"ls", "-la", "/home/" + testUsername})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode, "user home directory should exist")

	// Verify user has no password (disabled-password)
	exitCode, output, err = sshContainer.Exec(ctx, []string{"grep", testUsername, "/etc/shadow"})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)
	require.Contains(t, output, "!", "user should have disabled password")

	t.Log("✓ JIT user provisioning test passed successfully")
}

// TestJITUserProvisioningDisabled verifies that when JIT provisioning is disabled,
// SSH attempts with non-existent users fail as expected
func TestJITUserProvisioningDisabled(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Create local Docker network
	newNetwork, err := testcontainers.GenericNetwork(ctx, testcontainers.GenericNetworkRequest{
		NetworkRequest: testcontainers.NetworkRequest{
			Name:           "opkssh-jit-disabled-test-net",
			CheckDuplicate: true,
		},
	})
	require.NoError(t, err)
	defer func() {
		if err := newNetwork.Remove(ctx); err != nil {
			t.Logf("failed to terminate Docker network: %v", err)
		}
	}()

	// Start OIDC server
	authCallbackRedirectPort, err := GetAvailablePort()
	require.NoError(t, err)
	oidcContainer, err := testprovider.RunExampleOpContainer(
		ctx,
		"opkssh-jit-disabled-test-net",
		map[string]string{
			"REDIRECT_URIS": fmt.Sprintf("http://localhost:%d/login-callback", authCallbackRedirectPort),
			"USER_PASSWORD": "verysecure",
		},
		issuerPort,
	)
	require.NoError(t, err)
	defer func() {
		if err := oidcContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate OIDC container: %v", err)
		}
	}()

	// Start SSH server container
	issuerHostIp, err := oidcContainer.ContainerIP(ctx)
	require.NoError(t, err)

	sshContainer, err := ssh_server.RunOpkSshContainer(ctx, issuerHostIp, issuerPort, "opkssh-jit-disabled-test-net", true)
	require.NoError(t, err)
	defer func() {
		if err := sshContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate SSH container: %v", err)
		}
	}()

	// Ensure JIT provisioning is disabled (default state)
	exitCode, _, err := sshContainer.Exec(ctx, []string{"sh", "-c", "echo 'enabled false' > /etc/opk/nss-opkssh.conf"})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)

	// Create OPK SSH provider
	zitadelOp, customTransport := createZitadelOPKSshProvider(oidcContainer.Port, authCallbackRedirectPort)

	// Call login
	errCh := make(chan error)
	go func() {
		loginCmd := commands.LoginCmd{Fs: afero.NewOsFs()}
		err := loginCmd.Login(ctx, zitadelOp, false, "")
		errCh <- err
	}()

	// Wait for login-callback server
	timeoutErr := WaitForServer(ctx, fmt.Sprintf("http://localhost:%d", authCallbackRedirectPort), LoginCallbackServerTimeout)
	require.NoError(t, timeoutErr)

	// Do OIDC login
	DoOidcInteractiveLogin(t, customTransport, fmt.Sprintf("http://localhost:%d/login", authCallbackRedirectPort), "test-user@oidc.local", "verysecure")

	// Wait for login to complete
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	select {
	case loginErr := <-errCh:
		require.NoError(t, loginErr)
	case <-timeoutCtx.Done():
		t.Fatal(timeoutCtx.Err())
	}

	// Get SSH key
	pubKey, secKeyFilePath, err := GetOPKSshKey("")
	require.NoError(t, err)

	// Create signer
	certSigner, _ := createOpkSshSigner(t, pubKey, secKeyFilePath)

	// Test username that doesn't exist
	testUsername := "nonexistentuser456"

	// Add policy
	mockEmail := "test-user@oidc.local"
	mockIssuer := fmt.Sprintf("http://oidc.local:%s/", issuerPort)
	policyLine := fmt.Sprintf("%s %s %s", testUsername, mockEmail, mockIssuer)
	exitCode, _, err = sshContainer.Exec(ctx, []string{"sh", "-c", fmt.Sprintf("echo '%s' >> /etc/opk/auth_id", policyLine)})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)

	// Attempt SSH connection as non-existent user
	// This should FAIL because JIT provisioning is disabled
	authKey := goph.Auth{ssh.PublicKeys(certSigner)}
	_, err = goph.NewConn(&goph.Config{
		User:     testUsername,
		Addr:     sshContainer.Host,
		Port:     uint(sshContainer.Port),
		Auth:     authKey,
		Callback: ssh.InsecureIgnoreHostKey(),
		Timeout:  10 * time.Second,
	})
	require.Error(t, err, "SSH connection should fail without JIT provisioning for non-existent user")

	t.Log("✓ JIT provisioning disabled test passed successfully")
}
