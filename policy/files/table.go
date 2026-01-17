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
	"log"
	"strings"

	"github.com/kballard/go-shellquote"
)

type Table struct {
	rows [][]string
}

// NewTable creates a new Table from the given content.
func NewTable(content []byte) *Table {
	table := [][]string{}
	rows := strings.Split(string(content), "\n")
	for _, row := range rows {
		row := CleanRow(row)
		if row == "" {
			continue
		}
		columns, err := shellquote.Split(row)

		if err != nil {
			log.Printf("Unable to parse: %s. (%s), skipping...\n", row, err)
			continue
		}
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
		sb.WriteString(shellquote.Join(row...) + "\n")
	}
	return sb.String()
}

func (t Table) ToBytes() []byte {
	return []byte(t.ToString())
}

func (t Table) GetRows() [][]string {
	return t.rows
}

type RowDetails struct {
	Columns []string
	Content string
	Empty   bool
	Error   error
}

// ReadRowsWithDetails reads rows from content, returning any parsing errors.
// Useful for auditing and finding configuration problems.
func ReadRowsWithDetails(content []byte) []RowDetails {
	tableDetails := []RowDetails{}
	rows := strings.Split(string(content), "\n")
	for _, rowContent := range rows {
		row := CleanRow(rowContent)
		if row == "" {
			tableDetails = append(tableDetails,
				RowDetails{
					Empty:   true,
					Content: rowContent,
				})
			continue
		}

		columns, err := shellquote.Split(row)
		if err != nil {
			tableDetails = append(tableDetails, RowDetails{
				Error:   err,
				Content: rowContent,
			})
			log.Printf("Unable to parse: %s. (%s), skipping...\n", row, err)
			continue
		}
		tableDetails = append(tableDetails, RowDetails{
			Columns: columns,
			Content: rowContent,
		})
	}
	return tableDetails
}
