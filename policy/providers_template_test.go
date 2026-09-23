// Copyright 2026 OpenPubkey
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

package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/openpubkey/opkssh/policy/files"
	"github.com/stretchr/testify/require"
)

// installerProvidersTemplate extracts the providers file template that an
// installer script writes on a new install.
func installerProvidersTemplate(t *testing.T, script string, pattern string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "scripts", script))
	require.NoError(t, err)
	match := regexp.MustCompile(pattern).FindSubmatch(content)
	require.NotNil(t, match, "providers template not found in %s", script)
	return strings.ReplaceAll(string(match[1]), "\r\n", "\n")
}

// TestInstallerProvidersTemplate checks the providers file written by the
// Linux and Windows installers: both write the same template, and opkssh
// reads it as no providers, without config problems. Uncommenting a
// provider line, with or without replacing <CLIENT-ID>, gives a valid row.
func TestInstallerProvidersTemplate(t *testing.T) {
	linux := installerProvidersTemplate(t, "install-linux.sh", `(?s)providers_template\(\) \{\s*cat <<'EOF'\r?\n(.*?\n)EOF\r?\n`)
	windows := installerProvidersTemplate(t, filepath.Join("windows", "Install-OpksshServer.ps1"), `(?s)\$template = @'\r?\n(.*?\n)'@`)
	require.Equal(t, linux, windows, "install-linux.sh and Install-OpksshServer.ps1 must write the same providers template")

	path := filepath.Join(t.TempDir(), "providers")
	loader := ProvidersFileLoader{}
	require.Empty(t, loader.FromTable([]byte(linux), path).GetRows())
	require.Empty(t, problemsFor(path))

	providerLines := regexp.MustCompile(`(?m)^# (https://\S+ \S+ \S+)$`).FindAllStringSubmatch(linux, -1)
	require.Len(t, providerLines, 3)
	for _, line := range providerLines {
		for _, uncommented := range []string{line[1], strings.Replace(line[1], "<CLIENT-ID>", "my-client-id", 1)} {
			rows := loader.FromTable([]byte(uncommented+"\n"), path).GetRows()
			require.Len(t, rows, 1, uncommented)
			_, err := rows[0].GetExpirationPolicy()
			require.NoError(t, err, uncommented)
		}
	}
	require.Empty(t, problemsFor(path))
}

func problemsFor(path string) []files.ConfigProblem {
	problems := []files.ConfigProblem{}
	for _, problem := range files.ConfigProblems().GetProblems() {
		if problem.Filepath == path {
			problems = append(problems, problem)
		}
	}
	return problems
}
