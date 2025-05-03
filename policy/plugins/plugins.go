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

package plugins

import (
	"encoding/base64"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
	"gopkg.in/yaml.v3"
)

const requiredPolicyPerms = fs.FileMode(0640)
const requiredPolicyCmdPerms = fs.FileMode(0755)

type PluginResult struct {
	Path         string
	PluginConfig PluginConfig
	Error        error
	PolicyTrace  string
	Success      bool
}

type PluginResults []*PluginResult

func (r PluginResults) Errors() (errs []error) {
	for _, pluginResult := range r {
		if pluginResult.Error != nil {
			errs = append(errs, pluginResult.Error)
		}
	}
	return errs
}

func (r PluginResults) Allowed() bool {
	for _, pluginResult := range r {
		if pluginResult.Success {
			return true
		}
	}
	return false
}

type CmdExecutor func(name string, arg ...string) ([]byte, error)

func DefaultCmdExecutor(name string, arg ...string) ([]byte, error) {
	return exec.Command(name, arg...).CombinedOutput()
}

type PolicyPluginEnforcer struct {
	Fs          afero.Fs
	cmdExecutor CmdExecutor // This lets us mock command exec in unit tests
	permChecker files.PermsChecker
}

func NewPolicyPluginEnforcer() *PolicyPluginEnforcer {
	fs := afero.NewOsFs()
	return &PolicyPluginEnforcer{
		Fs:          fs,
		cmdExecutor: DefaultCmdExecutor,
		permChecker: files.PermsChecker{
			Fs:        fs,
			CmdRunner: files.ExecCmd,
		},
	}
}

// loadPlugins loads the plugin config files from the given directory.
func (p *PolicyPluginEnforcer) loadPlugins(dir string) (pluginResults PluginResults, err error) {
	filesFound, err := afero.ReadDir(p.Fs, dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range filesFound {
		path := filepath.Join(dir, entry.Name())
		info, err := p.Fs.Stat(path)
		if err != nil {
			return nil, err
		}

		if err := p.permChecker.CheckPerm(path, requiredPolicyPerms, "root", ""); err != nil {
			return nil, fmt.Errorf("policy plugin config file (%s) has insecure permissions: %w", path, err)
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".yml") {
			pluginResult := &PluginResult{}
			pluginResults = append(pluginResults, pluginResult)

			pluginResult.Path = path

			file, err := afero.ReadFile(p.Fs, path)
			if err != nil {
				pluginResult.Error = fmt.Errorf("failed to read file %s: %w", path, err)
				continue
			}

			var cmd PluginConfig
			if err := yaml.Unmarshal(file, &cmd); err != nil {
				pluginResult.Error = fmt.Errorf("failed to parse YAML in file %s: %w", path, err)
				continue
			}

			if cmd.Name == "" {
				pluginResult.Error = fmt.Errorf("policy plugin config missing required field 'name' in file %s:", path)
				continue
			}

			if cmd.CommandTemplate == "" {
				pluginResult.Error = fmt.Errorf("policy plugin config missing required field 'command' in file %s: ", path)
				continue
			}

			pluginResult.PluginConfig = cmd
		}
	}
	return pluginResults, nil
}

func (p *PolicyPluginEnforcer) CheckPolicies(dir string, pkt *pktoken.PKToken, principal string, sshCert string, keyType string) (PluginResults, error) {
	tokens, err := NewTokens(pkt, principal, sshCert, keyType)
	if err != nil {
		return nil, err
	}
	return p.checkPolicies(dir, tokens)
}

func (p *PolicyPluginEnforcer) checkPolicies(dir string, tokens map[string]string) (PluginResults, error) {
	pluginResults, err := p.loadPlugins(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy commands: %w", err)
	}
	for _, pluginResult := range pluginResults {
		if pluginResult.Error != nil {
			continue
		}
		output, err := p.executePolicyCommand(pluginResult.PluginConfig, tokens)
		pluginResult.Error = err
		pluginResult.PolicyTrace = string(output)
		if err != nil || string(output) != "allowed" {
			pluginResult.Success = false
		} else {
			pluginResult.Success = true
		}
	}
	return pluginResults, nil
}

// executePolicyCommand executes the policy command with the provided tokens.
func (p *PolicyPluginEnforcer) executePolicyCommand(config PluginConfig, tokens map[string]string) ([]byte, error) {
	// Add PluginConfig to the tokens map for expansion
	configJson, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config to JSON: %w", err)
	}
	tokens["%config%"] = base64.StdEncoding.EncodeToString(configJson)

	// Replace tokens in the command string.
	command, err := config.PercentExpand(tokens)
	if err != nil {
		return nil, err
	}

	if err := p.permChecker.CheckPerm(command[0], requiredPolicyCmdPerms, "root", ""); err != nil {
		if strings.Contains(err.Error(), "file does not exist") {
			return nil, err
		} else {
			return nil, fmt.Errorf("policy plugin command (%s) has insecure permissions: %w", command[0], err)
		}
	}

	return p.cmdExecutor(command[0], command[1:]...)
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
