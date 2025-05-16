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

package policy

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

var _ Loader = &MultiPolicyLoader{
	LoaderScript: ReadWithSudoScript,
}

// FileSource implements policy.Source by returning a string that is expected to
// be a filepath
type FileSource string

func (s FileSource) Source() string {
	return string(s)
}

func NewMultiPolicyLoader(username string, loader OptionalLoader) *MultiPolicyLoader {
	return &MultiPolicyLoader{
		HomePolicyLoader:   NewHomePolicyLoader(),
		SystemPolicyLoader: NewSystemPolicyLoader(),
		LoaderScript:       loader,
		Username:           username,
	}
}

// MultiPolicyLoader implements policy.Loader by reading both the system default
// policy (root policy) and user policy (~/.opk/auth_id where ~ maps to
// Username's home directory)
type MultiPolicyLoader struct {
	HomePolicyLoader   *HomePolicyLoader
	SystemPolicyLoader *SystemPolicyLoader
	LoaderScript       OptionalLoader
	Username           string
}

func (l *MultiPolicyLoader) Load() (*Policy, Source, error) {
	policy := new(Policy)

	// Try to load the root policy
	rootPolicy, _, rootPolicyErr := l.SystemPolicyLoader.LoadSystemPolicy()
	if rootPolicyErr != nil {
		log.Println("warning: failed to load system default policy:", rootPolicyErr)
	}

	// Try to load the user policy
	userPolicy, userPolicyFilePath, userPolicyErr := l.HomePolicyLoader.LoadHomePolicy(l.Username, true, l.LoaderScript)
	if userPolicyErr != nil {
		log.Println("warning: failed to load user policy:", userPolicyErr)
	}
	// Log warning if no error loading, but userPolicy is empty meaning that
	// there are no valid entries
	if userPolicyErr == nil && len(userPolicy.Users) == 0 {
		log.Printf("warning: user policy %s has no valid user entries; an entry is considered valid if it gives %s access.", userPolicyFilePath, l.Username)
	}

	// Failed to read both policies. Return multi-error
	if rootPolicy == nil && userPolicy == nil {
		return nil, EmptySource{}, errors.Join(rootPolicyErr, userPolicyErr)
	}

	// TODO-Yuval: Optimize by merging duplicate entries instead of blindly
	// appending
	readPaths := []string{}
	if rootPolicy != nil {
		policy.Users = append(policy.Users, rootPolicy.Users...)
		readPaths = append(readPaths, SystemDefaultPolicyPath)
	}
	if userPolicy != nil {
		policy.Users = append(policy.Users, userPolicy.Users...)
		readPaths = append(readPaths, userPolicyFilePath)
	}

	return policy, FileSource(strings.Join(readPaths, ", ")), nil
}

// ReadWithSudoScript specifies additional way of loading the policy in the
// user's home directory (`~/.opk/auth_id`). This is needed when the
// AuthorizedKeysCommand user does not have privileges to transverse the user's
// home directory. Instead we call run a command which uses special
// sudoers permissions to read the policy file.
//
// Doing this is more secure than simply giving opkssh sudoer access because
// if there was an RCE in opkssh could be triggered an SSH request via
// AuthorizedKeysCommand, the new opkssh process we use to perform the read
// would not be compromised. Thus, the compromised opkssh process could not assume
// full root privileges.
func ReadWithSudoScript(h *HomePolicyLoader, username string) ([]byte, error) {
	// opkssh readhome ensures the file is not a symlink and has the permissions/ownership.
	// The default path is /usr/local/bin/opkssh
	opkBin, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("error getting opkssh executable path: %w", err)
	}
	cmd := exec.Command("sudo", "-n", opkBin, "readhome", username)

	homePolicyFileBytes, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error reading %s home policy using command %v got output %v and err %v", username, cmd, string(homePolicyFileBytes), err)
	}
	return homePolicyFileBytes, nil
}
