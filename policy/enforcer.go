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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/opkssh/policy/plugins"
	"golang.org/x/exp/slices"
)

// Enforcer evaluates opkssh policy to determine if the desired principal is
// permitted
type Enforcer struct {
	PolicyLoader Loader
}

// type for Identity Token checkedClaims
type checkedClaims struct {
	Email  string   `json:"email"`
	Sub    string   `json:"sub"`
	Groups []string `json:"groups"`
}

// The default location for policy plugins
const pluginPolicyDir = "/etc/opk/policy.d"

// Validates that the server defined identity attribute matches the
// respective claim from the identity token
func validateClaim(claims *checkedClaims, user *User) bool {
	if strings.HasPrefix(user.IdentityAttribute, "oidc:groups") {
		oidcGroupSections := strings.Split(user.IdentityAttribute, ":")

		return slices.Contains(claims.Groups, oidcGroupSections[len(oidcGroupSections)-1])
	}

	// email should be a case-insensitive check
	// sub should be a case-sensitive check
	return strings.EqualFold(claims.Email, user.IdentityAttribute) || string(claims.Sub) == user.IdentityAttribute
}

// CheckPolicy loads opkssh policy and checks to see if there is a policy
// permitting access to principalDesired for the user identified by the PKT's
// email claim. Returns nil if access is granted. Otherwise, an error is
// returned.
//
// It is security critical to verify the pkt first before calling this function.
// This is because if this function is called first, a timing channel exists which
// allows an attacker check what identities and principals are allowed by the policy.F
func (p *Enforcer) CheckPolicy(principalDesired string, pkt *pktoken.PKToken, userInfoJson string, sshCert string, keyType string) error {
	pluginPolicy := plugins.NewPolicyPluginEnforcer()

	results, err := pluginPolicy.CheckPolicies(pluginPolicyDir, pkt, userInfoJson, principalDesired, sshCert, keyType)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Println("Skipping policy plugins: no plugins found at " + pluginPolicyDir)
		} else {
			log.Printf("Error checking policy plugins: %v \n", err)
		}
		// Despite the error, we don't fail here because we still want to check
		// the standard policy below. Policy plugins can only expand the set of
		// allow set, not shrink it.
	} else {
		for _, result := range results {
			commandRunStr := strings.Join(result.CommandRun, " ")
			log.Printf("Policy plugin result, path: (%s), allowed: (%t), error: (%v), command_run: (%s), policyOutput: (%s)\n", result.Path, result.Allowed, result.Error, commandRunStr, result.PolicyOutput)
		}
		if results.Allowed() {
			log.Printf("Access granted by policy plugin\n")
			return nil
		}
	}

	policy, source, err := p.PolicyLoader.Load()
	if err != nil {
		return fmt.Errorf("error loading policy: %w", err)
	}

	var claims checkedClaims

	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return fmt.Errorf("error unmarshalling pk token payload: %w", err)
	}
	issuer, err := pkt.Issuer()
	if err != nil {
		return fmt.Errorf("error getting issuer from pk token: %w", err)
	}

	var userInfoClaims *checkedClaims
	if userInfoJson != "" {
		userInfoClaims = new(checkedClaims)
		if err := json.Unmarshal([]byte(userInfoJson), userInfoClaims); err != nil {
			return fmt.Errorf("error unmarshalling claims from userinfo endpoint: %w", err)
		}
	}

	for _, user := range policy.Users {
		// The underlying library checks idT.sub == userInfo.sub when we call the userinfo endpoint.
		// We want to be extra sure so we also check it here as well.
		if userInfoClaims != nil && claims.Sub != userInfoClaims.Sub {
			return fmt.Errorf("userInfo sub claim (%s) does not match user policy sub claim (%s)", userInfoClaims.Sub, claims.Sub)
		}

		if issuer != user.Issuer {
			continue
		}

		// if they are, then check if the desired principal is allowed
		if !slices.Contains(user.Principals, principalDesired) {
			continue
		}

		// check each entry to see if the user in the checkedClaims is included
		if validateClaim(&claims, &user) {
			// access granted
			return nil
		}

		// check each entry to see if the user matches the userInfoClaims
		if userInfoClaims != nil && validateClaim(userInfoClaims, &user) {
			// access granted
			return nil
		}

	}

	return fmt.Errorf("no policy to allow %s with (issuer=%s) to assume %s, check policy config at %s", claims.Email, issuer, principalDesired, source.Source())
}
