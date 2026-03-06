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

package main

import (
	"bufio"
	"os"
	"strings"
	"unicode"
)

// LoadPrincipals reads /etc/opk/auth_id and returns the deduplicated list of
// Linux principals (column 1).  The file format is:
//
//	PRINCIPAL  IDENTITY_ATTRIBUTE  ISSUER
//
// Lines starting with # are comments.  Fields are whitespace-delimited and
// may be shell-quoted (double-quote only, for simplicity).
func LoadPrincipals(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := make(map[string]bool)
	var out []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comment
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}

		fields := splitFields(line)
		if len(fields) < 1 {
			continue
		}
		principal := fields[0]
		if principal == "" || seen[principal] {
			continue
		}
		seen[principal] = true
		out = append(out, principal)
	}
	return out, scanner.Err()
}

// splitFields splits a line on whitespace, handling double-quoted strings.
func splitFields(s string) []string {
	var fields []string
	var cur strings.Builder
	inQuote := false

	for i := 0; i < len(s); i++ {
		c := rune(s[i])
		switch {
		case c == '"':
			inQuote = !inQuote
		case !inQuote && unicode.IsSpace(c):
			if cur.Len() > 0 {
				fields = append(fields, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 {
		fields = append(fields, cur.String())
	}
	return fields
}
