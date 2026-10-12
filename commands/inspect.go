// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken"
	"golang.org/x/crypto/ssh"
)

type InspectCmd struct {
	// KeyOrCert is the SSH key or certificate to be inspected.
	KeyOrCert string
	// Output is where output should be written to.
	Output io.Writer
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

// Run inspects the key or certificate named by KeyOrCert. When KeyOrCert is
// empty, it discovers opkssh-generated certificates in the locations login
// writes them and prints every one it finds.
func (i *InspectCmd) Run() error {
	if i.KeyOrCert == "" {
		return i.runDiscovery()
	}

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
	for key, value := range cert.Extensions {
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

// runDiscovery looks for opkssh-generated certificates in the directories
// that `opkssh login` writes them to and prints the details of every one it
// finds. The search order matches the precedence login uses when choosing
// where to write keys, so the certificate login most recently wrote is
// printed first.
func (i *InspectCmd) runDiscovery() error {
	paths, err := DiscoverSSHCerts()
	if err != nil {
		return err
	}

	if len(paths) == 0 {
		i.printf("No opkssh generated SSH certificates found in ~/.ssh/%s or ~/.ssh\n", opkSshDirName)
		return nil
	}

	for _, path := range paths {
		i.printf("=== %s ===\n", path)
		inspect := &InspectCmd{KeyOrCert: path, Output: i.Output}
		if err := inspect.Run(); err != nil {
			i.printf("Error inspecting %s: %v\n", path, err)
		}
	}
	return nil
}

// runDiscoveryIn is runDiscovery with the ~/.ssh root made explicit for tests.
func (i *InspectCmd) runDiscoveryIn(sshPath string) error {
	paths, err := discoverSSHCertsIn(sshPath)
	if err != nil {
		return err
	}

	if len(paths) == 0 {
		i.printf("No opkssh generated SSH certificates found in ~/.ssh/%s or ~/.ssh\n", opkSshDirName)
		return nil
	}

	for _, path := range paths {
		i.printf("=== %s ===\n", path)
		inspect := &InspectCmd{KeyOrCert: path, Output: i.Output}
		if err := inspect.Run(); err != nil {
			i.printf("Error inspecting %s: %v\n", path, err)
		}
	}
	return nil
}

// opkSshDirName is the directory under ~/.ssh where `opkssh login --configure`
// writes key pairs, kept in sync with LoginCmd.writeKeysToOpkSSHDir.
const opkSshDirName = "opkssh"

// DiscoverSSHCerts returns the paths of opkssh-generated SSH certificate
// files found on the local filesystem, sorted for deterministic output. Both
// locations that `opkssh login` can write certificates to are searched:
//
//  1. ~/.ssh/opkssh/, for keys written when the opkssh identity directory is
//     configured or when an explicit --private-key-file lives there
//  2. ~/.ssh/, where login writes to the default ssh key file names
//
// Only files containing a certificate whose comment was set by opkssh
// (prefix "openpubkey") are returned, so certificates from other tools are
// never reported.
func DiscoverSSHCerts() ([]string, error) {
	homePath, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}
	return discoverSSHCertsIn(filepath.Join(homePath, ".ssh"))
}

// discoverSSHCertsIn is DiscoverSSHCerts with the ~/.ssh root made
// explicit. It exists so tests can run discovery against a throwaway
// directory instead of the user running the tests.
func discoverSSHCertsIn(sshPath string) ([]string, error) {

	var paths []string
	seen := make(map[string]bool)

	// 1. The opkssh identity directory. Every *-cert.pub file in it is a
	// candidate; login is the only writer of this directory.
	opkSSHDir := filepath.Join(sshPath, opkSshDirName)
	entries, err := os.ReadDir(opkSSHDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), "-cert.pub") {
				continue
			}
			path := filepath.Join(opkSSHDir, entry.Name())
			if isOpenpubkeyCert(path) {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	// 2. The default ssh key file names in ~/.ssh. Only these are ever
	// written by opkssh login, so other keys in ~/.ssh are left alone.
	for _, keyFilename := range allDefaultSSHKeyFileNames() {
		path := filepath.Join(sshPath, keyFilename+"-cert.pub")
		if seen[path] {
			continue
		}
		if isOpenpubkeyCert(path) {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	sort.Strings(paths)
	return paths, nil
}

// isOpenpubkeyCert reports whether the file at path holds an SSH
// certificate whose comment was written by opkssh. login writes the comment
// "openpubkey" (default ssh dir) or "openpubkey: <issuer> <audience>"
// (opkssh identity dir), so the openpubkey prefix identifies both.
func isOpenpubkeyCert(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	_, comment, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return false
	}
	// A bare public key in a -cert.pub file parses the same way; only the
	// comment distinguishes opkssh output, and opkssh never writes a bare
	// key into a *-cert.pub file.
	return strings.HasPrefix(comment, "openpubkey")
}
