// Copyright 2024 OpenPubkey
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
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/verifier"
	"golang.org/x/crypto/ssh"
)

type SshCertSmuggler struct {
	SshCert *ssh.Certificate
}

func New(pkt *pktoken.PKToken, accessToken []byte, principals []string) (*SshCertSmuggler, error) {

	// TODO: assumes email exists in ID Token,
	// this will break for OPs like Azure that do not have email as a claim
	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return nil, err
	}

	pubkeySsh, err := sshPubkeyFromPKT(pkt)
	if err != nil {
		return nil, err
	}
	pktCom, err := pkt.Compact()
	if err != nil {
		return nil, err
	}

	extensions := map[string]string{
		"permit-X11-forwarding":   "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
		"permit-pty":              "",
		"permit-user-rc":          "",
		"openpubkey-pkt":          string(pktCom),
	}

	if accessToken != nil {
		extensions["openpubkey-act"] = string(accessToken)
	}

	sshSmuggler := SshCertSmuggler{
		SshCert: &ssh.Certificate{
			Key:             pubkeySsh,
			CertType:        ssh.UserCert,
			KeyId:           claims.Email,
			ValidPrincipals: principals,
			ValidBefore:     ssh.CertTimeInfinity,
			Permissions: ssh.Permissions{
				Extensions: extensions,
			},
		},
	}
	return &sshSmuggler, nil
}

func NewFromAuthorizedKey(certType string, certB64 string) (*SshCertSmuggler, error) {
	authorizedKeyStr := certType + " " + certB64
	if certPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKeyStr)); err != nil {
		return nil, err
	} else {
		sshCert, ok := certPubkey.(*ssh.Certificate)
		if !ok {
			// Get the actual type for debugging
			actualType := fmt.Sprintf("%T", certPubkey)

			// Truncate the base64 data for display (show first 50 chars)
			truncatedB64 := certB64
			if len(certB64) > 50 {
				truncatedB64 = certB64[:50] + "..."
			}

			return nil, fmt.Errorf("parsed SSH authorized_key is not an SSH certificate. Got type: %s, Key type: %s, Base64 (truncated): %s. Expected a certificate (key type should end with '-cert-v01@openssh.com')",
				actualType, certType, truncatedB64)
		}
		opkcert := &SshCertSmuggler{
			SshCert: sshCert,
		}
		return opkcert, nil
	}
}

func (s *SshCertSmuggler) SignCert(signerMas ssh.MultiAlgorithmSigner) (*ssh.Certificate, error) {
	if err := s.SshCert.SignCert(rand.Reader, signerMas); err != nil {
		return nil, err
	}
	return s.SshCert, nil
}

func (s *SshCertSmuggler) VerifyCaSig(caPubkey ssh.PublicKey) error {
	certCopy := *(s.SshCert)
	certCopy.Signature = nil
	certBytes := certCopy.Marshal()
	certBytes = certBytes[:len(certBytes)-4] // Drops signature length bytes (see crypto.ssh.certs.go)
	return caPubkey.Verify(certBytes, s.SshCert.Signature)
}

func (s *SshCertSmuggler) GetPKToken() (*pktoken.PKToken, error) {
	pktCom, ok := s.SshCert.Extensions["openpubkey-pkt"]
	if !ok {
		return nil, fmt.Errorf("cert is missing required openpubkey-pkt extension")
	}
	pkt, err := pktoken.NewFromCompact([]byte(pktCom))
	if err != nil {
		return nil, fmt.Errorf("openpubkey-pkt extension in cert failed deserialization: %w", err)
	}
	return pkt, nil
}

func (s *SshCertSmuggler) GetAccessToken() string {
	// Generally we don't expect this to be set, but if it is, we return it
	if accessToken, ok := s.SshCert.Extensions["openpubkey-act"]; ok {
		return accessToken
	}
	return ""
}

func (s *SshCertSmuggler) VerifySshPktCert(ctx context.Context, pktVerifier verifier.Verifier) (*pktoken.PKToken, error) {
	pkt, err := s.GetPKToken()
	if err != nil {
		return nil, fmt.Errorf("openpubkey-pkt extension in cert failed deserialization: %w", err)
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err = pktVerifier.VerifyPKToken(ctxWithTimeout, pkt)
	if err != nil {
		return nil, err
	}

	cic, err := pkt.GetCicValues()
	if err != nil {
		return nil, err
	}
	upk := cic.PublicKey()

	cryptoCertKey := (s.SshCert.Key.(ssh.CryptoPublicKey)).CryptoPublicKey()
	jwkCertKey, err := jwk.FromRaw(cryptoCertKey)
	if err != nil {
		return nil, err
	}

	if jwk.Equal(jwkCertKey, upk) {
		return pkt, nil
	} else {
		return nil, fmt.Errorf("public key 'upk' in PK Token does not match public key in certificate")
	}
}

func sshPubkeyFromPKT(pkt *pktoken.PKToken) (ssh.PublicKey, error) {
	cic, err := pkt.GetCicValues()
	if err != nil {
		return nil, err
	}
	upk := cic.PublicKey()

	var rawkey any
	if err := upk.Raw(&rawkey); err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(rawkey)
}
