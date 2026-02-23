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
	"bytes"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/kballard/go-shellquote"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
	"gopkg.in/yaml.v3"
)

const requiredPolicyPerms = fs.FileMode(0640)

var requiredPolicyDirPerms = []fs.FileMode{fs.FileMode(0700), fs.FileMode(0750), fs.FileMode(0755)}

var requiredPolicyCmdPerms = []fs.FileMode{fs.FileMode(0555), fs.FileMode(0755)}

// RequiredPolicyDirPerms returns the list of acceptable directory permission
// modes for the policy plugin directory. Exported for use by external code.
func RequiredPolicyDirPerms() []fs.FileMode {
	return requiredPolicyDirPerms
}

type PluginResult struct {
	Path         string
	PluginConfig PluginConfig
	Error        error
	CommandRun   []string
	PolicyOutput string
	Allowed      bool
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
		if pluginResult.Allowed {
			if pluginResult.PolicyOutput != "allow" {
				// This uses a double-entry bookkeeping approach to catch
				// security critical bugs.
				// Allowed is only set to true if the policy plugin command
				// returns exactly "allow" and we set PolicyOutput to the
				// value that the policy plugin command returned. Thus if
				// (PolicyOutput != "allow") AND (Allowed == true) something
				// went epically wrong and we should panic.
				// This should never happen.
				panic(fmt.Sprintf("Danger!!! Policy plugin command (%s) returned 'allow' but the plugin command did not approve. If you encounter this, report this as a vulnerability.", pluginResult.Path))
			}
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
	// Ensure the /opk/ssh/policy.d can only be written by root
	if err := p.permChecker.CheckPerm(dir, requiredPolicyDirPerms, "root", ""); err != nil {
		return nil, fmt.Errorf("policy plugin directory (%s) has insecure permissions: %w", dir, err)
	}

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

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".yml") {
			pluginResult := &PluginResult{}
			pluginResults = append(pluginResults, pluginResult)
			pluginResult.Path = path

			if err := p.permChecker.CheckPerm(path, []fs.FileMode{requiredPolicyPerms}, "root", ""); err != nil {
				pluginResult.Error = fmt.Errorf("policy plugin config file (%s) has insecure permissions: %w", path, err)
				continue
			}

			file, err := afero.ReadFile(p.Fs, path)
			if err != nil {
				pluginResult.Error = fmt.Errorf("failed to read policy plugin config at (%s): %w", path, err)
				continue
			}

			var cmd PluginConfig
			if err := yaml.Unmarshal(file, &cmd); err != nil {
				pluginResult.Error = fmt.Errorf("failed to parse YAML in policy plugin config at (%s): %w", path, err)
				continue
			}

			if cmd.Name == "" {
				pluginResult.Error = fmt.Errorf("policy plugin config missing required field 'name' in policy plugin config at (%s)", path)
				continue
			}

			if cmd.Command == "" {
				pluginResult.Error = fmt.Errorf("policy plugin config missing required field 'command' in policy plugin config at (%s): ", path)
				continue
			}

			pluginResult.PluginConfig = cmd
		}
	}
	return pluginResults, nil
}

// CheckPolicies loads the policies plugin configs in the directory dir
// and then runs the policy command specified in which policy plugin config
// to determine if the user is allowed to assume access as the given principal.
// It returns PluginResults for each plugin configs found in the policy
// plugin directory.
//
// Run PluginResults.Allowed() to determine if the user is allowed to
// assume access.
//
// CheckPolicies does not short circuit if a policy returns allow. This is to
// enable admins to do a test rollout of a new policy plugin without needing to
// disable the old policy plugin until they are sure the new policy plugin is
// working correctly.
func (p *PolicyPluginEnforcer) CheckPolicies(dir string, pkt *pktoken.PKToken, userInfoJson string, principal string, sshCert string, keyType string, extraArgs []string) (PluginResults, error) {
	tokens, err := PopulatePluginEnvVars(pkt, userInfoJson, principal, sshCert, keyType, extraArgs)
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
		// Only run the command in the plugin config if there was no error loading the plugin config
		if pluginResult.Error == nil {
			commandRun, output, err := p.executePolicyCommand(pluginResult.PluginConfig, tokens)
			output = bytes.TrimSpace(output)
			pluginResult.Error = err
			pluginResult.PolicyOutput = string(output)
			pluginResult.CommandRun = commandRun
			if err != nil {
				pluginResult.Error = fmt.Errorf("failed to run policy command %s got error (%w)", pluginResult.PluginConfig.Command, err)
				continue
			} else if string(output) != "allow" {
				pluginResult.Allowed = false
			} else {
				pluginResult.Allowed = true
			}
		}
	}
	return pluginResults, nil
}

// executePolicyCommand executes the policy command with the provided tokens.
func (p *PolicyPluginEnforcer) executePolicyCommand(config PluginConfig, inputEnvVars map[string]string) ([]string, []byte, error) {
	// Add PluginConfig to the tokens map for expansion
	configJson, err := yaml.Marshal(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal config to JSON: %w", err)
	}
	inputEnvVars["OPKSSH_PLUGIN_CONFIG"] = base64.StdEncoding.EncodeToString(configJson)

	// Ensure we don't use any environment variables as an input to
	// the policy plugin command that this process inherited. We only
	// want to pass values we set ourselves.
	for _, envVar := range os.Environ() {
		if strings.HasPrefix(envVar, "OPKSSH_PLUGIN_") {
			os.Unsetenv(strings.Split(envVar, "=")[0])
		}
	}

	for envK, envV := range inputEnvVars {
		if err := os.Setenv(envK, envV); err != nil {
			return nil, nil, fmt.Errorf("failed to set environment variable %s: %w", envK, err)
		}
	}

	command, err := shellquote.Split(config.Command)
	if err != nil {
		return nil, nil, err
	}

	if err := p.permChecker.CheckPerm(command[0], requiredPolicyCmdPerms, "root", ""); err != nil {
		if strings.Contains(err.Error(), "file does not exist") {
			return nil, nil, err
		} else {
			return nil, nil, fmt.Errorf("policy plugin command (%s) has insecure permissions: %w", command[0], err)
		}
	}

	output, err := p.cmdExecutor(command[0], command[1:]...)
	return command, output, err
}

// b64 is a simple helper function to base64 encode a string.
func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
