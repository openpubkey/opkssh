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

package files

import (
	"strings"
	"unicode"
)

// fieldsEscaped splits a string on whitespace boundaries, but preserves
// whitespace that is escaped with a backslash. This allows for values
// containing spaces to be represented in the policy file.
func fieldsEscaped(s string) []string {
	var currentField strings.Builder
	escaped := false
	fields := []string{}

	for _, r := range s {
		if escaped { // This will write the next character (including if it's an escape character or space)
			// If we're in escaped mode, add the character regardless of what it is
			currentField.WriteRune(r)
			escaped = false
			continue
		}

		if r == '\\' {
			// Enter escaped mode for the next character
			escaped = true
			continue
		}

		if unicode.IsSpace(r) {
			// We found a space and we're not in escaped mode, so this is a field boundary
			if currentField.Len() > 0 {
				fields = append(fields, currentField.String())
				currentField.Reset()
			}
		} else {
			// Not a space, add to current field
			currentField.WriteRune(r)
		}
	}

	// Add the last field if there is one
	if currentField.Len() > 0 {
		fields = append(fields, currentField.String())
	}

	return fields
}

// writeEscaped takes an array of strings and returns a single string with each
// element separated by a space. Any spaces or backslashes within the input strings
// are escaped with a backslash to preserve them when parsing with fieldsEscaped.
func writeEscaped(fields []string) string {
	var result strings.Builder

	for i, field := range fields {
		if i > 0 {
			result.WriteRune(' ')
		}

		for _, r := range field {
			// Escape backslashes and spaces
			if r == '\\' || unicode.IsSpace(r) {
				result.WriteRune('\\')
			}
			result.WriteRune(r)
		}
	}

	return result.String()
}

type Table struct {
	rows [][]string
}

func NewTable(content []byte) *Table {
	table := [][]string{}
	rows := strings.Split(string(content), "\n")
	for _, row := range rows {
		row := CleanRow(row)
		if row == "" {
			continue
		}
		// Parse the row using fieldsEscaped to handle escaped spaces and backslashes
		columns := fieldsEscaped(row)
		table = append(table, columns)
	}
	return &Table{rows: table}
}

func CleanRow(row string) string {
	// Remove comments
	rowFixed := strings.Split(row, "#")[0]
	// Skip empty rows
	rowFixed = strings.TrimSpace(rowFixed)
	return rowFixed
}

func (t *Table) AddRow(row ...string) {
	t.rows = append(t.rows, row)
}

func (t Table) ToString() string {
	var sb strings.Builder
	for _, row := range t.rows {
		sb.WriteString(writeEscaped(row) + "\n")
	}
	return sb.String()
}

func (t Table) ToBytes() []byte {
	return []byte(t.ToString())
}

func (t Table) GetRows() [][]string {
	return t.rows
}
