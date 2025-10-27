//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/melbahja/goph"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/opkssh/commands"
	"github.com/openpubkey/opkssh/sshcert"
	testprovider "github.com/openpubkey/opkssh/test/integration/provider"
	"github.com/openpubkey/opkssh/test/integration/ssh_server"
	"github.com/stretchr/testify/require"
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

	// Create a mock OIDC provider
	providerOpts := providers.DefaultMockProviderOpts()
	providerOpts.GQSign = true
	providerOpts.Issuer = fmt.Sprintf("http://oidc.local:%s", issuerPort)
	mockProvider, _, idtTemplate, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)

	mockEmail := "jituser@example.com"
	idtTemplate.ExtraClaims = map[string]any{
		"email": mockEmail,
	}

	// Start OIDC provider server
	issuer, issuerCleanup, err := testprovider.StartIssuerContainer(ctx, mockProvider, issuerPort, networkName)
	require.NoError(t, err)
	defer issuerCleanup()

	// Start SSH server container with OPKSSH and NSS module
	sshContainer, err := ssh_server.RunOpkSshContainer(ctx, issuer.GetIP(), issuerPort, networkName, true)
	require.NoError(t, err)
	defer func() {
		if err := sshContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate SSH container: %v", err)
		}
	}()

	// Enable JIT user provisioning in the container
	_, _, err = sshContainer.Exec(ctx, []string{"sh", "-c", "echo 'enabled true' >> /etc/opk/nss-opkssh.conf"})
	require.NoError(t, err)

	_, _, err = sshContainer.Exec(ctx, []string{"sh", "-c", "echo 'auto_provision_users: true' >> /etc/opk/config.yml"})
	require.NoError(t, err)

	// Verify NSS module is installed and configured
	exitCode, output, err := sshContainer.Exec(ctx, []string{"getent", "passwd", "nonexistentuser_jit"})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode, "getent should succeed with NSS module enabled")
	require.Contains(t, output, "nonexistentuser_jit", "NSS module should return user info")
	require.Contains(t, output, "65534", "NSS module should return UID 65534")

	// Create OPKSSH login and generate SSH certificate
	ciClient := clientinstance.New(mockProvider,
		clientinstance.WithSignGQ(true),
	)

	pkt, err := ciClient.OidcAuth(ctx, idtTemplate, nil)
	require.NoError(t, err)

	// Generate SSH key pair
	sshKeyPair, err := sshcert.GenerateKeyPair(sshcert.ECDSA)
	require.NoError(t, err)

	// Create SSH certificate with PK token
	sshCert, err := sshcert.New(sshKeyPair.PublicKey, pkt, nil)
	require.NoError(t, err)

	// Sign the SSH certificate
	caSigner, err := sshcert.NewCASigner(sshKeyPair.PrivateKey)
	require.NoError(t, err)

	certifiedPubKey, err := caSigner.SignCert(sshCert.SshCert)
	require.NoError(t, err)

	// Create SSH auth method with the signed certificate
	authMethod := goph.RawKey(string(ssh.MarshalAuthorizedKey(certifiedPubKey)), sshKeyPair.PrivateKey)

	// Test username that doesn't exist on the system
	testUsername := "jituser123"

	// Verify user doesn't exist initially
	exitCode, output, err = sshContainer.Exec(ctx, []string{"id", testUsername})
	require.NoError(t, err)
	require.NotEqual(t, 0, exitCode, "user should not exist before SSH login")
	require.Contains(t, output, "no such user", "expected user not found error")

	// Add policy to allow the mock email to SSH as testUsername
	addPolicy := commands.AddCmd{
		Username: testUsername,
	}
	policyFilePath := "/etc/opk/auth_id"
	policyLine := fmt.Sprintf("%s %s %s", testUsername, mockEmail, mockProvider.Issuer())

	_, _, err = sshContainer.Exec(ctx, []string{"sh", "-c", fmt.Sprintf("echo '%s' >> %s", policyLine, policyFilePath)})
	require.NoError(t, err)

	// Attempt SSH connection as the non-existent user
	// This should trigger JIT user provisioning
	sshClient, err := goph.NewConn(&goph.Config{
		User:     testUsername,
		Addr:     sshContainer.Host,
		Port:     uint(sshContainer.Port),
		Auth:     authMethod,
		Callback: ssh.InsecureIgnoreHostKey(),
		Timeout:  30 * time.Second,
	})
	require.NoError(t, err, "SSH connection should succeed with JIT provisioning")
	defer sshClient.Close()

	// Verify we can execute commands
	output, err = sshClient.Run("whoami")
	require.NoError(t, err)
	require.Equal(t, testUsername, strings.TrimSpace(string(output)), "SSH session should be as the provisioned user")

	// Verify user was actually created on the system
	exitCode, output, err = sshContainer.Exec(ctx, []string{"id", testUsername})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode, "user should exist after SSH login")
	require.Contains(t, output, testUsername, "id command should return the username")

	// Verify user's home directory was created
	exitCode, output, err = sshContainer.Exec(ctx, []string{"ls", "-la", "/home/" + testUsername})
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

	// Create a mock OIDC provider
	providerOpts := providers.DefaultMockProviderOpts()
	providerOpts.GQSign = true
	providerOpts.Issuer = fmt.Sprintf("http://oidc.local:%s", issuerPort)
	mockProvider, _, idtTemplate, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)

	mockEmail := "testuser@example.com"
	idtTemplate.ExtraClaims = map[string]any{
		"email": mockEmail,
	}

	// Start OIDC provider server
	issuer, issuerCleanup, err := testprovider.StartIssuerContainer(ctx, mockProvider, issuerPort, networkName)
	require.NoError(t, err)
	defer issuerCleanup()

	// Start SSH server container with OPKSSH but JIT disabled
	sshContainer, err := ssh_server.RunOpkSshContainer(ctx, issuer.GetIP(), issuerPort, networkName, true)
	require.NoError(t, err)
	defer func() {
		if err := sshContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate SSH container: %v", err)
		}
	}()

	// Ensure JIT provisioning is disabled (default state)
	_, _, err = sshContainer.Exec(ctx, []string{"sh", "-c", "echo 'enabled false' > /etc/opk/nss-opkssh.conf"})
	require.NoError(t, err)

	// Create OPKSSH login and generate SSH certificate
	ciClient := clientinstance.New(mockProvider,
		clientinstance.WithSignGQ(true),
	)

	pkt, err := ciClient.OidcAuth(ctx, idtTemplate, nil)
	require.NoError(t, err)

	// Generate SSH key pair
	sshKeyPair, err := sshcert.GenerateKeyPair(sshcert.ECDSA)
	require.NoError(t, err)

	// Create SSH certificate with PK token
	sshCert, err := sshcert.New(sshKeyPair.PublicKey, pkt, nil)
	require.NoError(t, err)

	// Sign the SSH certificate
	caSigner, err := sshcert.NewCASigner(sshKeyPair.PrivateKey)
	require.NoError(t, err)

	certifiedPubKey, err := caSigner.SignCert(sshCert.SshCert)
	require.NoError(t, err)

	// Create SSH auth method with the signed certificate
	authMethod := goph.RawKey(string(ssh.MarshalAuthorizedKey(certifiedPubKey)), sshKeyPair.PrivateKey)

	// Test username that doesn't exist on the system
	testUsername := "nonexistentuser456"

	// Add policy to allow the mock email to SSH as testUsername
	policyLine := fmt.Sprintf("%s %s %s", testUsername, mockEmail, mockProvider.Issuer())
	_, _, err = sshContainer.Exec(ctx, []string{"sh", "-c", fmt.Sprintf("echo '%s' >> /etc/opk/auth_id", policyLine)})
	require.NoError(t, err)

	// Attempt SSH connection as the non-existent user
	// This should FAIL because JIT provisioning is disabled
	_, err = goph.NewConn(&goph.Config{
		User:     testUsername,
		Addr:     sshContainer.Host,
		Port:     uint(sshContainer.Port),
		Auth:     authMethod,
		Callback: ssh.InsecureIgnoreHostKey(),
		Timeout:  10 * time.Second,
	})
	require.Error(t, err, "SSH connection should fail without JIT provisioning for non-existent user")

	t.Log("✓ JIT provisioning disabled test passed successfully")
}
