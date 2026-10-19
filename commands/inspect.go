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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/opkssh/policy"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type InspectCmd struct {
	// KeyOrCert is the SSH key or certificate to be inspected.
	KeyOrCert string
	// Output is where output should be written to.
	Output io.Writer
	// ErrOutput is where warnings are written. Nil means os.Stderr.
	ErrOutput io.Writer
}

// NewInspectCmd creates a new InspectCmd instance with the provided arguments.
func NewInspectCmd(keyOrCert string, output io.Writer) *InspectCmd {
	return &InspectCmd{
		KeyOrCert: keyOrCert,
		Output:    output,
	}
}

// printf formats a string to the configured output. If writing fails, it
// falls back to standard output rather than retrying the failing writer.
func (i *InspectCmd) printf(format string, a ...any) {
	if _, err := fmt.Fprintf(i.Output, format, a...); err != nil {
		fmt.Fprintf(os.Stdout, format, a...)
	}
}

func (i *InspectCmd) warnf(format string, a ...any) {
	errOutput := i.ErrOutput
	if errOutput == nil {
		errOutput = os.Stderr
	}
	fmt.Fprintf(errOutput, format, a...)
}

// Run inspects KeyOrCert, which is either a file path or the key or certificate itself.
func (i *InspectCmd) Run() error {
	// Check if the input is a file path
	if _, err := os.Stat(i.KeyOrCert); err == nil {
		// It's a file, read its contents
		data, err := os.ReadFile(i.KeyOrCert)
		if err != nil {
			return fmt.Errorf("error reading input file: %v", err)
		}
		i.KeyOrCert = string(data)
	}

	// Trim whitespace and newlines
	i.KeyOrCert = strings.TrimSpace(i.KeyOrCert)

	// Parse the SSH key or certificate
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(i.KeyOrCert))
	if err != nil {
		return fmt.Errorf("failed to parse SSH key: %v", err)
	}

	// Check if it's a certificate
	if cert, ok := pubKey.(*ssh.Certificate); ok {
		i.inspectCertificate(cert)
	} else {
		// It's a regular public key
		i.inspectPublicKey(pubKey)
	}

	return nil
}

func (i *InspectCmd) inspectCertificate(cert *ssh.Certificate) {
	i.printf("--- SSH Certificate Information ---\n")
	i.printf("%-18s %d\n", "Serial:", cert.Serial)
	i.printf("%-18s %s\n", "Type:", certificateType(cert.CertType))
	i.printf("%-18s %s\n", "Key ID:", cert.KeyId)
	i.printf("%-18s %v\n", "Principals:", cert.ValidPrincipals)
	i.printf("%-18s %s\n", "Valid After:", formatTime(cert.ValidAfter))
	i.printf("%-18s %s\n", "Valid Before:", formatTime(cert.ValidBefore))
	i.printf("%-18s %v\n", "Critical Options:", cert.CriticalOptions)

	// Format extensions nicely
	i.printf("Extensions:\n")
	for _, key := range slices.Sorted(maps.Keys(cert.Extensions)) {
		value := cert.Extensions[key]
		if key == "openpubkey-pkt" {
			i.printf("  %s: [PKToken data] %d bytes\n", key, len(value))
		} else {
			i.printf("  %s: %s\n", key, value)
		}
	}

	// Extract openpubkey-pkt extension if it exists
	pktStr, ok := cert.Extensions["openpubkey-pkt"]
	if !ok {
		i.printf("\nNo openpubkey-pkt extension found\n")
		return
	}

	i.inspectPKToken(pktStr)
}

// formatTime converts a Unix timestamp to a readable date string
func formatTime(timestamp uint64) string {
	if timestamp == 0 {
		return "Not set"
	}
	if timestamp == 1<<64-1 {
		return "Forever"
	}
	t := time.Unix(int64(timestamp), 0)
	return t.Format(time.RFC3339)
}

func (i *InspectCmd) inspectPublicKey(pubKey ssh.PublicKey) {
	i.printf("--- SSH Public Key Information ---\n")
	i.printf("Type: %s\n", pubKey.Type())

	// Get fingerprint
	fingerprint := ssh.FingerprintSHA256(pubKey)
	i.printf("Fingerprint: %s\n", fingerprint)

	// Get marshal format
	marshal := base64.StdEncoding.EncodeToString(pubKey.Marshal())
	i.printf("Marshal (base64): %s...\n", marshal[:20])
}

func certificateType(certType uint32) string {
	switch certType {
	case ssh.UserCert:
		return "User Certificate"
	case ssh.HostCert:
		return "Host Certificate"
	}
	return fmt.Sprintf("Unknown (%d)", certType)
}

func (i *InspectCmd) inspectPKToken(pktStr string) {
	// Parse the PKToken
	pkt, err := pktoken.NewFromCompact([]byte(pktStr))
	if err != nil {
		i.printf("Error parsing PKToken: %v\n", err)
		return
	}

	// Print token structure and metadata
	i.printf("\n--- PKToken Structure ---\n")
	i.printf("Payload:\n")
	i.printJSON(pkt.Payload)

	// Print signature information
	i.printf("\n--- Signature Information ---\n")
	if pkt.Op != nil {
		i.printf("Provider Signature (OP) exists\n")
		hdrs := pkt.Op.ProtectedHeaders()
		if hdrs != nil {
			i.printJSONObject(hdrs)
		}
	}
	if pkt.Cic != nil {
		i.printf("Client Signature (CIC) exists\n")
		hdrs := pkt.Cic.ProtectedHeaders()
		if hdrs != nil {
			i.printJSONObject(hdrs)
		}
	}
	if pkt.Cos != nil {
		i.printf("Cosigner Signature (COS) exists\n")
		hdrs := pkt.Cos.ProtectedHeaders()
		if hdrs != nil {
			i.printJSONObject(hdrs)
		}
	}
	if pkt.FreshIDToken != nil {
		i.printf("Refreshed ID Token exists\n")
		parsedReIdt, err := oidc.NewJwt(pkt.FreshIDToken)
		if err != nil {
			i.printf("Error parsing refreshed ID token: %v\n", err)
		} else {
			if prettyReIdt, err := parsedReIdt.PrettyJson(); err != nil {
				i.printf("Error pretty-printing refreshed ID token: %v\n", err)
			} else {
				i.printf("%s\n", prettyReIdt)
			}
		}
	}

	// Print token metadata
	i.printf("\n--- Token Metadata ---\n")
	i.printTokenMetadata(pkt)
	i.printExpiration(pkt)
}

func (i *InspectCmd) printJSON(data []byte) {
	var obj any
	if err := json.Unmarshal(data, &obj); err != nil {
		i.printf("Error unmarshalling JSON: %v\n", err)
		i.printf("%s\n", string(data))
		return
	}

	i.printJSONObject(obj)
}

func (i *InspectCmd) printJSONObject(obj any) {
	pretty, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		i.printf("Error pretty-printing: %v\n", err)
		i.printf("%v\n", obj)
		return
	}

	i.printf("%s\n", string(pretty))
}

func (i *InspectCmd) printTokenMetadata(pkt *pktoken.PKToken) {
	// Extract common token claims
	if issuer, err := pkt.Issuer(); err == nil {
		i.printf("%-19s %s\n", "Issuer:", issuer)
	}

	if aud, err := pkt.Audience(); err == nil {
		i.printf("%-19s %s\n", "Audience:", aud)
	}

	if sub, err := pkt.Subject(); err == nil {
		i.printf("%-19s %s\n", "Subject:", sub)
	}

	if identity, err := pkt.IdentityString(); err == nil {
		i.printf("%-19s %s\n", "Identity:", identity)
	}

	// Print token hash (useful for identifying tokens)
	if hash, err := pkt.Hash(); err == nil {
		i.printf("%-19s %s\n", "Token Hash:", hash)
	}

	// Print provider algorithm if available
	if alg, ok := pkt.ProviderAlgorithm(); ok {
		i.printf("%-19s %s\n", "Provider Algorithm:", alg)
	}
}

// expirationPolicyNames lists the expiration policies a server can set in
// /etc/opk/providers, in the order inspect prints them.
var expirationPolicyNames = []string{"12h", "24h", "48h", "1week", "oidc", "oidc_refreshed", "never"}

var expirationPolicyMaxAges = map[string]time.Duration{
	"12h":   12 * time.Hour,
	"24h":   24 * time.Hour,
	"48h":   48 * time.Hour,
	"1week": 7 * 24 * time.Hour,
}

// printExpiration shows, for each server expiration policy, when the PK token
// stops being accepted. The SSH certificate itself never expires; the server
// decides from the ID token.
func (i *InspectCmd) printExpiration(pkt *pktoken.PKToken) {
	idt, err := oidc.NewJwt(pkt.OpToken)
	if err != nil {
		i.printf("Error parsing ID token: %v\n", err)
		return
	}
	claims := idt.GetClaims()

	i.printf("\n--- Expiration by Server Policy ---\n")
	for _, name := range expirationPolicyNames {
		expirationPolicy, err := policy.ProvidersRow{ExpirationPolicy: name}.GetExpirationPolicy()
		if err != nil {
			i.printf("%-19s %v\n", name+":", err)
			continue
		}
		status := "valid"
		if expirationPolicy.CheckExpiration(pkt) != nil {
			status = "expired"
		}
		i.printf("%-19s %-25s %s\n", name+":", policyExpiresAt(name, claims, pkt), status)
	}
}

func policyExpiresAt(name string, claims *oidc.OidcClaims, pkt *pktoken.PKToken) string {
	switch name {
	case "never":
		return "Never"
	case "oidc":
		return formatUnixTime(claims.Expiration)
	case "oidc_refreshed":
		// Accepted while either the ID token or the refreshed ID token is unexpired.
		expiration := claims.Expiration
		if pkt.FreshIDToken != nil {
			if freshIdt, err := oidc.NewJwt(pkt.FreshIDToken); err == nil {
				expiration = max(expiration, freshIdt.GetClaims().Expiration)
			}
		}
		return formatUnixTime(expiration)
	default:
		if claims.IssuedAt <= 0 {
			return "Unknown"
		}
		return time.Unix(claims.IssuedAt, 0).Add(expirationPolicyMaxAges[name]).Format(time.RFC3339)
	}
}

func formatUnixTime(seconds int64) string {
	if seconds <= 0 {
		return "Unknown"
	}
	return time.Unix(seconds, 0).Format(time.RFC3339)
}

// RunDiscovery inspects every opkssh certificate found in ~/.ssh/opkssh,
// under the default key names in ~/.ssh, and in the ssh-agent at
// SSH_AUTH_SOCK.
func (i *InspectCmd) RunDiscovery() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}
	return i.inspectCertsIn(filepath.Join(homeDir, ".ssh"))
}

func (i *InspectCmd) inspectCertsIn(sshDir string) error {
	certFiles, readErrs := findOpkSSHCerts(sshDir)
	for _, err := range readErrs {
		i.warnf("Warning: %v\n", err)
	}
	agentSock := os.Getenv("SSH_AUTH_SOCK")
	agentCerts, err := listOpkSSHAgentCerts(agentSock)
	if err != nil {
		i.warnf("Warning: could not list ssh-agent certificates (%s): %v\n", agentSock, err)
	}

	if len(certFiles) == 0 && len(agentCerts) == 0 {
		searched := filepath.Join(sshDir, opkSSHDirName) + " or " + sshDir
		if agentSock != "" {
			searched = filepath.Join(sshDir, opkSSHDirName) + ", " + sshDir + " or ssh-agent"
		}
		i.printf("No opkssh certificates found in %s\n", searched)
		i.printf("For a key written with `opkssh login -i <path>`, run `opkssh inspect <path>-cert.pub`\n")
		return nil
	}

	printed := 0
	inspectOne := func(header string, cert *ssh.Certificate) {
		if printed > 0 {
			i.printf("\n")
		}
		printed++
		i.printf("=== %s ===\n", header)
		i.inspectCertificate(cert)
	}
	for _, certFile := range certFiles {
		inspectOne(certFile.Path, certFile.Cert)
	}
	for _, cert := range agentCerts {
		inspectOne("ssh-agent "+ssh.FingerprintSHA256(cert.Key), cert)
	}
	return nil
}

// listOpkSSHAgentCerts returns the opkssh certificates in the ssh-agent at
// sock. An empty sock means there is no agent to ask.
func listOpkSSHAgentCerts(sock string) ([]*ssh.Certificate, error) {
	if sock == "" {
		return nil, nil
	}
	conn, err := dialSSHAgent(sock)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	keys, err := agent.NewClient(conn).List()
	if err != nil {
		return nil, err
	}
	var certs []*ssh.Certificate
	for _, key := range keys {
		// Not filtered on the comment: ssh-add sets it to the key's file path.
		pubKey, err := ssh.ParsePublicKey(key.Blob)
		if err != nil {
			continue
		}
		if cert, ok := pubKey.(*ssh.Certificate); ok && cert.Extensions["openpubkey-pkt"] != "" {
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

// opkSSHDirName is the directory under ~/.ssh that LoginCmd.writeKeysToOpkSSHDir writes to.
const opkSSHDirName = "opkssh"

type opkSSHCertFile struct {
	Path string
	Cert *ssh.Certificate
}

// findOpkSSHCerts returns, sorted by path, the opkssh certificates that login
// can have written under sshDir, plus any errors other than "does not exist"
// hit while looking. Each file is read once, so what is printed is what was
// checked.
func findOpkSSHCerts(sshDir string) ([]opkSSHCertFile, []error) {
	var candidates []string
	var readErrs []error

	opkDir := filepath.Join(sshDir, opkSSHDirName)
	entries, err := os.ReadDir(opkDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		readErrs = append(readErrs, err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), "-cert.pub") {
			candidates = append(candidates, filepath.Join(opkDir, entry.Name()))
		}
	}
	for _, keyFileName := range allDefaultSSHKeyFileNames() {
		candidates = append(candidates, filepath.Join(sshDir, keyFileName+"-cert.pub"))
	}

	var certFiles []opkSSHCertFile
	for _, path := range candidates {
		cert, err := readOpkSSHCertFile(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			readErrs = append(readErrs, err)
		}
		if cert != nil {
			certFiles = append(certFiles, opkSSHCertFile{Path: path, Cert: cert})
		}
	}
	sort.Slice(certFiles, func(a, b int) bool { return certFiles[a].Path < certFiles[b].Path })
	return certFiles, readErrs
}

// readOpkSSHCertFile returns the certificate in path, or nil if path doesn't
// hold an opkssh certificate.
func readOpkSSHCertFile(path string) (*ssh.Certificate, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	// Reading a FIFO or device would block forever.
	if !info.Mode().IsRegular() {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, nil
	}
	cert, isCert := pubKey.(*ssh.Certificate)
	if !isCert || !isOpenpubkeyComment(data) {
		return nil, nil
	}
	return cert, nil
}
