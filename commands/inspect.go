// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

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

// printf formats a string to the configured output.
func (i *InspectCmd) printf(format string, a ...any) {
	if _, err := fmt.Fprintf(i.Output, format, a...); err != nil {
		// Fall back to stdout
		i.printf(format, a...)
	}
}

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
	}
	if pkt.Cic != nil {
		i.printf("Client Signature (CIC) exists\n")
	}
	if pkt.Cos != nil {
		i.printf("Cosigner Signature (COS) exists\n")
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

	pretty, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		i.printf("Error pretty-printing: %v\n", err)
		i.printf("%s\n", string(data))
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
