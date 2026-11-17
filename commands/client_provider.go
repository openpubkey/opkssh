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

package commands

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/openpubkey/openpubkey/client/choosers"
	"github.com/openpubkey/opkssh/commands/config"
	"github.com/spf13/afero"
	"gopkg.in/yaml.v3"
)

// ClientProviderAddCmd adds an OpenID Provider to the client config
// (~/.opk/config.yml), so that `opkssh login <alias>` uses your own client ID.
type ClientProviderAddCmd struct {
	Fs  afero.Fs
	Out io.Writer

	ConfigPath   string
	Alias        string
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       string
	Replace      bool
}

// NewClientProviderAddCmd creates a ClientProviderAddCmd that edits the client config on disk
func NewClientProviderAddCmd(out io.Writer) *ClientProviderAddCmd {
	return &ClientProviderAddCmd{
		Fs:  afero.NewOsFs(),
		Out: out,
	}
}

// Run adds the provider to the client config, creating the config from the
// default client config if it does not exist. The config file is edited in
// place so that its comments are kept.
func (c *ClientProviderAddCmd) Run() error {
	if err := config.ResolveClientConfigPath(&c.ConfigPath); err != nil {
		return err
	}
	// Edit the file a symlinked config points to, so the rename below
	// replaces the target rather than the symlink.
	configPath, err := resolveSymlinks(c.Fs, c.ConfigPath)
	if err != nil {
		return err
	}

	// Build the updated config in memory and only write it once it is valid,
	// so that a failed add never creates or changes the config file.
	created := false
	perm := config.ClientConfigFilePerms
	content, err := afero.ReadFile(c.Fs, configPath)
	if os.IsNotExist(err) {
		content = config.DefaultClientConfig
		created = true
	} else if err != nil {
		return fmt.Errorf("failed to read client config %s: %w", configPath, err)
	} else if info, err := c.Fs.Stat(configPath); err != nil {
		return err
	} else if info.Mode().Perm()&0o200 == 0 {
		// Respect a config the user made read-only. On Unix the rename below
		// would replace it anyway, and on Windows it would fail.
		return fmt.Errorf("client config %s is read-only", configPath)
	} else {
		perm = info.Mode().Perm()
	}

	updated, replaced, err := c.addProvider(content)
	if err != nil {
		return fmt.Errorf("%s: %w", c.ConfigPath, err)
	}

	if created {
		if err := c.Fs.MkdirAll(filepath.Dir(configPath), config.ClientConfigDirPerms); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
	}
	// Write to a temporary file and rename it, so a failure never leaves a truncated config
	tmpPath := configPath + ".tmp"
	if err := afero.WriteFile(c.Fs, tmpPath, updated, perm); err != nil {
		return fmt.Errorf("failed to write client config: %w", err)
	}
	if err := c.Fs.Rename(tmpPath, configPath); err != nil {
		_ = c.Fs.Remove(tmpPath)
		return fmt.Errorf("failed to write client config: %w", err)
	}

	if created {
		fmt.Fprintf(c.Out, "Created client config %s from the default config\n", c.ConfigPath)
	}
	action := "Added"
	if replaced {
		action = "Replaced"
	}
	fmt.Fprintf(c.Out, "%s provider %s (%s) in %s\n", action, c.Alias, c.Issuer, c.ConfigPath)
	fmt.Fprintf(c.Out, "Servers must trust this client ID. On each server, add this line to /etc/opk/providers:\n")
	fmt.Fprintf(c.Out, "  %s %s 24h\n", c.Issuer, c.ClientID)
	return nil
}

// resolveSymlinks returns the path that path points to when it is a symlink
// on the OS filesystem, and path otherwise. Only a path that is itself a
// symlink is resolved: on Windows, OneDrive folders, junctions and other
// reparse points are not reported as symlinks (Go 1.23+), so they are left as
// they are rather than being rewritten by filepath.EvalSymlinks.
func resolveSymlinks(fs afero.Fs, path string) (string, error) {
	if _, ok := fs.(*afero.OsFs); !ok {
		return path, nil
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) || (err == nil && info.Mode()&os.ModeSymlink == 0) {
		return path, nil
	} else if err != nil {
		return "", fmt.Errorf("failed to read client config path %s: %w", path, err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("failed to resolve symlinked client config %s: %w", path, err)
	}
	return resolved, nil
}

// addProvider returns the client config with the provider added, or with the
// provider that has the same alias replaced, and whether it replaced one.
func (c *ClientProviderAddCmd) addProvider(content []byte) ([]byte, bool, error) {
	if strings.TrimSpace(c.Alias) == "" || strings.ContainsAny(c.Alias, " \t") {
		return nil, false, fmt.Errorf("invalid provider alias %q", c.Alias)
	}
	newProvider := config.DefaultProviderConfig()
	newProvider.AliasList = []string{c.Alias}
	newProvider.Issuer = c.Issuer
	newProvider.ClientID = c.ClientID
	newProvider.ClientSecret = c.ClientSecret
	if strings.HasSuffix(c.Issuer, "/") {
		// The issuer must match the iss claim of the ID token exactly, which has no trailing slash
		return nil, false, fmt.Errorf("issuer must not end with /: %s", c.Issuer)
	}
	if strings.HasPrefix(c.Issuer, "https://accounts.google.com") && c.ClientSecret == "" {
		// Google requires the client secret even for public clients; it is not a secret for them.
		return nil, false, fmt.Errorf("the Google OpenID Provider requires --client-secret")
	}
	if _, err := newProvider.ToProvider(false); err != nil {
		return nil, false, err
	}
	// The login web chooser shows one button per OpenID Provider name, so two
	// providers whose issuers map to the same name break it.
	newName, err := choosers.IssuerToName(c.Issuer)
	if err != nil {
		return nil, false, err
	}

	// The YAML encoder turns the \r of CRLF line endings in comments into
	// extra line breaks, so work on LF line endings and restore them at the end
	crlf := bytes.Contains(content, []byte("\r\n"))
	content = bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n"))

	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, false, fmt.Errorf("failed to parse client config: %w", err)
	}
	if doc.Kind == 0 {
		// Empty file
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, false, fmt.Errorf("client config is not a YAML mapping")
	}
	root := doc.Content[0]
	providersNode := mappingValue(root, "providers")
	if providersNode == nil {
		providersNode = &yaml.Node{Kind: yaml.SequenceNode}
		root.Content = append(root.Content, scalarNode("providers"), providersNode)
	}
	if providersNode.Kind != yaml.SequenceNode {
		return nil, false, fmt.Errorf("providers in client config is not a list")
	}

	var existing *yaml.Node
	for _, providerNode := range providersNode.Content {
		aliases := []string{}
		issuer := ""
		if v := mappingValue(providerNode, "alias"); v != nil {
			aliases = strings.Fields(v.Value)
		}
		if v := mappingValue(providerNode, "issuer"); v != nil {
			issuer = v.Value
		}
		if slices.Contains(aliases, c.Alias) {
			existing = providerNode
		} else if name, err := choosers.IssuerToName(issuer); issuer == c.Issuer || (err == nil && name == newName) {
			if len(aliases) == 0 {
				return nil, false, fmt.Errorf("a provider without an alias already uses issuer %s", issuer)
			}
			if issuer != c.Issuer {
				return nil, false, fmt.Errorf("provider %s uses issuer %s, which the login web chooser cannot tell apart from %s",
					strings.Join(aliases, " "), issuer, c.Issuer)
			}
			return nil, false, fmt.Errorf("provider %s already uses issuer %s; to use your client ID with it, run the same command with alias %s and --replace",
				strings.Join(aliases, " "), issuer, aliases[0])
		}
	}

	replaced := existing != nil
	if replaced && !c.Replace {
		return nil, false, fmt.Errorf("provider %s already exists; use --replace to replace it", c.Alias)
	}
	if !replaced {
		existing = &yaml.Node{Kind: yaml.MappingNode}
		setMappingValue(existing, "alias", c.Alias)
		providersNode.Content = append(providersNode.Content, existing)
	}
	// Replacing keeps the provider's other aliases and settings, such as its
	// scopes and redirect URIs, and changes only what belongs to the client ID.
	setMappingValue(existing, "issuer", c.Issuer)
	setMappingValue(existing, "client_id", c.ClientID)
	if c.ClientSecret != "" {
		setMappingValue(existing, "client_secret", c.ClientSecret)
	} else {
		deleteMappingKey(existing, "client_secret")
	}
	if c.Scopes != "" {
		setMappingValue(existing, "scopes", c.Scopes)
	}

	var buf bytes.Buffer
	if bytes.HasPrefix(content, []byte("---")) {
		// The encoder drops the document start marker
		buf.WriteString("---\n")
	}
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(&doc); err != nil {
		return nil, false, err
	}
	if err := encoder.Close(); err != nil {
		return nil, false, err
	}
	updated := restoreBlankLines(content, buf.Bytes())
	if crlf {
		updated = bytes.ReplaceAll(updated, []byte("\n"), []byte("\r\n"))
	}

	// Check that opkssh can load the result before it is written
	clientConfig, err := config.NewClientConfig(updated)
	if err != nil {
		return nil, false, fmt.Errorf("updated client config does not parse: %w", err)
	}
	if _, err := clientConfig.GetProvidersMap(); err != nil {
		return nil, false, err
	}
	return updated, replaced, nil
}

// restoreBlankLines puts back the blank lines of original, which the YAML
// encoder drops, before the lines that followed them in original.
func restoreBlankLines(original []byte, updated []byte) []byte {
	originalLines := strings.Split(string(original), "\n")
	afterBlank := map[string]bool{}
	for i := 1; i < len(originalLines); i++ {
		if strings.TrimSpace(originalLines[i-1]) == "" && strings.TrimSpace(originalLines[i]) != "" {
			afterBlank[originalLines[i]] = true
		}
	}

	var out strings.Builder
	previousBlank := true
	for _, line := range strings.SplitAfter(string(updated), "\n") {
		content := strings.TrimSuffix(line, "\n")
		if afterBlank[content] && !previousBlank {
			out.WriteString("\n")
			delete(afterBlank, content)
		}
		out.WriteString(line)
		previousBlank = strings.TrimSpace(content) == ""
	}
	return []byte(out.String())
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func setMappingValue(mapping *yaml.Node, key string, value string) {
	if v := mappingValue(mapping, key); v != nil {
		// Keep the node, and so any comment on its line
		v.Kind, v.Tag, v.Value, v.Style, v.Content = yaml.ScalarNode, "!!str", value, 0, nil
		return
	}
	mapping.Content = append(mapping.Content, scalarNode(key), scalarNode(value))
}

func deleteMappingKey(mapping *yaml.Node, key string) {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content = append(mapping.Content[:i], mapping.Content[i+2:]...)
			return
		}
	}
}

func scalarNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}
