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

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/openpubkey/opkssh/commands/config"
	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/openpubkey/opkssh/sshcert"
	"github.com/spf13/afero"
	"golang.org/x/crypto/ssh"
)

// PolicyEnforcerFunc returns nil if the supplied PK token is permitted to login as
// username. Otherwise, an error is returned indicating the reason for rejection
type PolicyEnforcerFunc func(username string, pkt *pktoken.PKToken, sshCert string, keyType string) error

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
}

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
// The following lines are added to /etc/ssh/sshd_config:
//
//	AuthorizedKeysCommand /usr/local/bin/opkssh ver %u %k %t
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
func (v *VerifyCmd) AuthorizedKeysCommand(ctx context.Context, userArg string, typArg string, certB64Arg string) (string, error) {
	// Parse the b64 pubkey and expect it to be an ssh certificate
	cert, err := sshcert.NewFromAuthorizedKey(typArg, certB64Arg)
	if err != nil {
		return "", err
	}
	if pkt, err := cert.VerifySshPktCert(ctx, v.PktVerifier); err != nil { // Verify the PKT contained in the cert
		return "", err
	} else if err := v.CheckPolicy(userArg, pkt, certB64Arg, typArg); err != nil { // Check if username is authorized
		return "", err
	} else { // Success!
		// sshd expects the public key in the cert, not the cert itself. This
		// public key is key of the CA that signs the cert, in our setting there
		// is no CA.
		pubkeyBytes := ssh.MarshalAuthorizedKey(cert.SshCert.SignatureKey)
		return "cert-authority " + string(pubkeyBytes), nil
	}
}

// SetEnvVarInConfig sets the environment variables specified in the server config file
func (v *VerifyCmd) SetEnvVarInConfig() error {
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
	return serverConfig.SetEnvVars()
}

// OpkPolicyEnforcerAuthFunc returns an opkssh policy.Enforcer that can be
// used in the opkssh verify command.
func OpkPolicyEnforcerFunc(username string) PolicyEnforcerFunc {
	policyEnforcer := &policy.Enforcer{
		PolicyLoader: policy.NewMultiPolicyLoader(username, policy.ReadWithSudoScript),
	}
	return policyEnforcer.CheckPolicy
}
