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
	"fmt"
	"io/fs"
	"net/http"
	"regexp"
	"strings"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/openpubkey/opkssh/commands/config"
	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/openpubkey/opkssh/sshcert"
	"github.com/spf13/afero"
	"golang.org/x/crypto/ssh"
)

// Conservative allowlist: covers POSIX usernames and the sentinel.
// Excludes " \ , whitespace and control chars, so neither the quoted
// option syntax nor the comma-join can be broken by construction.
var validPrincipal = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._+@-]{0,127}\$?$`)

// PolicyEnforcerFunc returns nil if the supplied PK token is permitted to login as
// username. Otherwise, an error is returned indicating the reason for rejection
type PolicyEnforcerFunc func(username string, pkt *pktoken.PKToken, userInfo string, sshCert string, keyType string, denyList policy.DenyList, extraArgs []string) error

// VerifyCmd provides functionality to verify OPK tokens contained in SSH
// certificates and authorize requests to SSH as a specific username using a
// configurable authorization system. It is designed to be used in conjunction
// with sshd's AuthorizedKeysCommand feature.
type VerifyCmd struct {
	Fs afero.Fs
	// PktVerifier is responsible for verifying the PK token
	// contained in the SSH certificate
	PktVerifier verifier.Verifier
	// CheckPolicy determines whether the verified PK token is permitted to SSH as a
	// specific user
	CheckPolicy PolicyEnforcerFunc
	// ConfigPathArg is the path to the server config file
	ConfigPathArg string
	// filePermChecker is used to check the file permissions of the config file
	filePermChecker files.PermsChecker
	// HTTPClient can be mocked using a roundtripper in tests
	HttpClient *http.Client
	// denyList is populated from ServerConfig after successful parsing
	denyList policy.DenyList
}

// NewVerifyCmd creates a new VerifyCmd instance with the provided arguments.
func NewVerifyCmd(pktVerifier verifier.Verifier, checkPolicy PolicyEnforcerFunc, configPathArg string) *VerifyCmd {
	fs := afero.NewOsFs()
	return &VerifyCmd{
		Fs:            fs,
		PktVerifier:   pktVerifier,
		CheckPolicy:   checkPolicy,
		ConfigPathArg: configPathArg,
		filePermChecker: files.PermsChecker{
			Fs:        fs,
			CmdRunner: files.ExecCmd,
		},
	}
}

// This function is called by the SSH server as the AuthorizedKeysCommand:
//
// By default, the following lines are added to the sshd_config at /etc/ssh/sshd_config.d/60-opk-ssh.conf:
//
//	AuthorizedKeysCommand /usr/local/bin/opkssh verify %u %k %t
//	AuthorizedKeysCommandUser opksshuser
//
// The parameters specified in the config map the parameters sent to the function below.
// We prepend "Arg" to specify which ones are arguments sent by sshd. They are:
//
//	%u The username (requested principal) - userArg
//	%k The base64-encoded public key for authentication - certB64Arg - the public key is also a certificate
//	%t The public key type - typArg - in this case a certificate being used as a public key
//
// AuthorizedKeysCommand verifies the OPK PK token contained in the base64-encoded SSH pubkey;
// the pubkey is expected to be an SSH certificate. pubkeyType is used to
// determine how to parse the pubkey as one of the SSH certificate types.
//
// This function:
// 1. Verifying the PK token with the OP (OpenID Provider)
// 2. Enforcing policy by checking if the identity is allowed to assume
// the username (principal) requested.
//
// If all steps of verification succeed, then the expected authorized_keys file
// format string is returned (i.e. the expected line to produce on standard
// output when using sshd's AuthorizedKeysCommand feature). Otherwise, a non-nil
// error is returned.
func (v *VerifyCmd) AuthorizedKeysCommand(ctx context.Context, userArg string, typArg string, certB64Arg string, extraArgs []string) (string, error) {
	// Parse the b64 pubkey and expect it to be an ssh certificate
	cert, err := sshcert.NewFromAuthorizedKey(typArg, certB64Arg)
	if err != nil {
		return "", err
	}

	if pkt, err := cert.VerifySshPktCert(ctx, v.PktVerifier); err != nil { // Verify the PKT contained in the cert
		return "", err
	} else {
		userInfo := ""
		if accessToken := cert.GetAccessToken(); accessToken != "" {
			if userInfoRet, err := v.UserInfoLookup(ctx, pkt, accessToken); err == nil {
				// userInfo is optional so we should not fail if we can't access it
				userInfo = userInfoRet
			}
		}

		if err := v.CheckPolicy(userArg, pkt, userInfo, certB64Arg, typArg, v.denyList, extraArgs); err != nil {
			return "", err
		} else { // Success!
			// sshd expects the public key in the cert, not the cert itself. This
			// public key is key of the CA that signs the cert, in our setting there
			// is no CA.
			pubkeyBytes := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert.SshCert.SignatureKey)))

			// Ensure principals in ssh cert are safe to use in the authorized_keys line
			if err := errorOnUnsafePrincipal(cert.SshCert.ValidPrincipals); err != nil {
				return "", err
			}

			principals := strings.Join(cert.SshCert.ValidPrincipals, ",")
			if principals != "" {
				// Makes sshd trust the principals in the certificate.
				// This is needed to emulate a principal wildcard in an SSH cert.
				// OpenSSH intentionally broke the old way of doing SSH cert principal
				// wildcards requiring OPKSSH to use this approach instead.
				// See https://github.com/openpubkey/opkssh/pull/513
				return fmt.Sprintf("cert-authority,principals=\"%s\" %s", principals, pubkeyBytes), nil
			}

			return fmt.Sprintf("cert-authority %s", pubkeyBytes), nil
		}
	}
}

// ReadFromServerConfig sets the environment variables specified in the server config file
// and assigns configured deny lists to VerifyCmd's denyList
func (v *VerifyCmd) ReadFromServerConfig() error {
	var configBytes []byte

	// Load the file from the filesystem
	afs := &afero.Afero{Fs: v.Fs}
	configBytes, err := afs.ReadFile(v.ConfigPathArg)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	err = v.filePermChecker.CheckPerm(v.ConfigPathArg, []fs.FileMode{0640}, "root", "opksshuser")
	if err != nil {
		return err
	}

	serverConfig, err := config.NewServerConfig(configBytes)
	if err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}
	v.denyList = policy.DenyList{
		Emails: serverConfig.DenyEmails,
		Users:  serverConfig.DenyUsers,
	}
	return serverConfig.SetEnvVars()
}

func (v *VerifyCmd) UserInfoLookup(ctx context.Context, pkt *pktoken.PKToken, accessToken string) (string, error) {
	ui, err := verifier.NewUserInfoRequester(pkt, accessToken)
	if err != nil {
		return "", err
	}
	ui.HttpClient = v.HttpClient
	return ui.Request(ctx)
}

// OpkPolicyEnforcerAuthFunc returns an opkssh policy.Enforcer that can be
// used in the opkssh verify command.
func OpkPolicyEnforcerFunc(username string) PolicyEnforcerFunc {
	policyEnforcer := &policy.Enforcer{
		PolicyLoader: policy.NewMultiPolicyLoader(username, policy.ReadWithSudoScript),
	}
	return policyEnforcer.CheckPolicy
}

// errorOnUnsafePrincipal checks if the principals contains any strings which
// should not be allowed in the authorized keys line output. For instance
// a principal containing whitespace or control characters could allow a
// user specified principal to change other parts of the
// AuthorizedKeysCommand output. The security risk here is small because
// we have already verified the user is allowed to assume the desired account,
// but it is worth locking down anyways.
// The obvious solution is to simply set the principals to the desired username,
// but this is not possible due to the use of the opkssh-wildcard trick used
// to solve issue 513 "Fix for openssh 10.3 breaking principals wildcard in SSH certificates"
func errorOnUnsafePrincipal(principals []string) error {
	for _, p := range principals {
		if !validPrincipal.MatchString(p) {
			return fmt.Errorf("cert contains invalid principal %q, rejecting authn", p)
		}
	}
	return nil
}
