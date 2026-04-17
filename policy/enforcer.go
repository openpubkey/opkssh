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
	"path/filepath"
	"strings"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/opkssh/policy/plugins"
	"golang.org/x/exp/slices"
)

const (
	OIDC_CLAIMS         = "oidc:"
	OIDC_WILDCARD_EMAIL = "oidc-match-end:email:"
)

// DenyList represents the DenyLists in the server config
type DenyList struct {
	Emails []string
	Users  []string
}

// Enforcer evaluates opkssh policy to determine if the desired principal is
// permitted
type Enforcer struct {
	PolicyLoader Loader
}

// type for Identity Token checkedClaims
type checkedClaims struct {
	Email       string              `json:"email"`
	Sub         string              `json:"sub"`
	ExtraClaims map[string][]string `json:"-"`
}

func (s *checkedClaims) UnmarshalJSON(data []byte) error {

	// Avoid infinite recursion
	type checkedClaimsAlias checkedClaims
	var a checkedClaimsAlias

	// Unmarshal the required claims
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*s = checkedClaims(a)

	// Unmarshal everything else
	var schema map[string]interface{}
	err := json.Unmarshal([]byte(data), &schema)
	if err != nil {
		return err
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	s.ExtraClaims = make(map[string][]string, len(raw))

	for k, v := range raw {
		switch t := v.(type) {
		case string:
			s.ExtraClaims[k] = []string{t}
		case []any:
			// Turn all elements in a list into a string
			out := make([]string, 0, len(t))
			for _, e := range t {
				if s, ok := e.(string); ok {
					out = append(out, s)
				} else {
					out = append(out, fmt.Sprint(e))
				}
			}
			s.ExtraClaims[k] = out
		default:
			// Turn numbers/bools etc into strings
			s.ExtraClaims[k] = []string{fmt.Sprint(t)}
		}
	}

	return nil
}

// GetPluginPolicyDir returns the default location for policy plugins.
// On Unix: /etc/opk/policy.d, On Windows: %ProgramData%\opk\policy.d
func GetPluginPolicyDir() string {
	return filepath.Join(GetSystemConfigBasePath(), "policy.d")
}

// EscapedSplit splits a string by a separator while ignoring the separator in quoted sections.
// This is useful for strings that may contain the separator character as part of the string
// and not as a delimiter.
func EscapedSplit(s string, sep rune) []string {
	quoted := false
	a := strings.FieldsFunc(s, func(r rune) bool {
		if r == '"' {
			quoted = !quoted
		}
		return !quoted && r == sep
	})
	return a
}

// Validates that the server defined identity attribute matches the
// respective claim from the identity token
func validateClaim(claims *checkedClaims, user *User) bool {
	// Should we match on the email claim?
	if strings.HasPrefix(claims.Email, OIDC_WILDCARD_EMAIL) {
		return false
	}

	// Should we match on an oidc claim?
	if strings.HasPrefix(user.IdentityAttribute, OIDC_CLAIMS) {
		oidcGroupSections := EscapedSplit(user.IdentityAttribute, ':')
		oidcGroupsName := strings.Trim(oidcGroupSections[1], "\"")

		return slices.Contains(
			claims.ExtraClaims[oidcGroupsName],
			oidcGroupSections[len(oidcGroupSections)-1],
		)
	}

	// Should we match on the email wildcard claim?
	wildCardEmailMatch := false
	if strings.HasPrefix(user.IdentityAttribute, OIDC_WILDCARD_EMAIL) {
		if strings.HasSuffix(strings.ToLower(claims.Email), strings.ToLower(user.IdentityAttribute[len(OIDC_WILDCARD_EMAIL):len(user.IdentityAttribute)])) {
			wildCardEmailMatch = true
		}
	}
	// email should be a case-insensitive check
	// sub should be a case-sensitive check
	return wildCardEmailMatch || strings.EqualFold(claims.Email, user.IdentityAttribute) || string(claims.Sub) == user.IdentityAttribute
}

// CheckPolicy loads opkssh policy and checks to see if there is a policy
// permitting access to principalDesired for the user identified by the PKT's
// email claim. Returns nil if access is granted. Otherwise, an error is
// returned.
//
// It is security critical to verify the pkt first before calling this function.
// This is because if this function is called first, a timing channel exists which
// allows an attacker check what identities and principals are allowed by the policy.F
func (p *Enforcer) CheckPolicy(principalDesired string, pkt *pktoken.PKToken, userInfoJson string, sshCert string, keyType string, denyList DenyList, extraArgs []string) error {

	var claims checkedClaims

	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return fmt.Errorf("error unmarshalling pk token payload: %w", err)
	}
	issuer, err := pkt.Issuer()
	if err != nil {
		return fmt.Errorf("error getting issuer from pk token: %w", err)
	}

	// Enforce deny list first
	for _, email := range denyList.Emails {
		if strings.EqualFold(claims.Email, email) {
			return fmt.Errorf("denied email %s", email)
		}
	}
	for _, user := range denyList.Users {
		if strings.EqualFold(principalDesired, user) {
			return fmt.Errorf("denied user %s", user)
		}
	}

	pluginPolicy := plugins.NewPolicyPluginEnforcer()
	pluginPolicyDir := GetPluginPolicyDir()

	results, err := pluginPolicy.CheckPolicies(pluginPolicyDir, pkt, userInfoJson, principalDesired, sshCert, keyType, extraArgs)
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
