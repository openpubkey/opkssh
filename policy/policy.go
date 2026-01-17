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
	"fmt"
	"log"
	"strings"

	"github.com/openpubkey/opkssh/policy/files"
)

// User is an opkssh policy user entry
type User struct {
	// IdentityAttribute is a string that is either structured or unstructured.
	// Structured: <IdentityProtocolMatching>:<Attribute>:<Value>
	// E.g. `oidc:groups:ssh-users`
	// Using the structured identifier allows the capability of constructing
	// complex user matchers.
	//
	// Unstructured:
	// This is older version that only works with OIDC Identity Tokens, with
	// the claim being `email` or `sub`. The expected value is to be the user's
	// email or the user's subscriber ID. The expected value used when comparing
	// against an id_token's email claim Subscriber ID is a unique identifier
	// for the user at the OpenID Provider
	IdentityAttribute string
	// Principals is a list of allowed principals
	Principals []string
	// Sub        string
	Issuer string
}

// Policy represents an opkssh policy
type Policy struct {
	// Users is a list of all user entries in the policy
	Users []User
}

// FromTable decodes whitespace delimited input into policy.Policy.
// Any problems encountered during parsing are returned. When verifying,
// these problems should be ignored so that a error on one line does not
// prevent all users from logging in.
func FromTable(input []byte, path string) (*Policy, []files.ConfigProblem) {
	problems := []files.ConfigProblem{}
	table := files.NewTable(input)
	policy := &Policy{}
	for _, row := range table.GetRows() {
		// Error should not break everyone's ability to login, skip those rows
		if len(row) != 3 {
			configProblem := files.ConfigProblem{
				Filepath:      path,
				OffendingLine: strings.Join(row, " "),
				ErrorMessage:  fmt.Sprintf("wrong number of arguments (expected=3, got=%d)", len(row)),
				Source:        "user policy file",
			}
			problems = append(problems, configProblem)
			files.ConfigProblems().RecordProblem(configProblem)
			continue
		}
		user := User{
			Principals:        []string{row[0]},
			IdentityAttribute: row[1],
			Issuer:            row[2],
		}
		policy.Users = append(policy.Users, user)
	}
	return policy, problems
}

// AddAllowedPrincipal adds a new allowed principal to the user whose email is
// equal to userEmail. If no user can be found with the email userEmail, then a
// new user entry is added with an initial allowed principals list containing
// principal. No changes are made if the principal is already allowed for this
// user.
func (p *Policy) AddAllowedPrincipal(principal string, userEmail string, issuer string) {
	var firstMatchingEntry *User // First entry that matches on userEmail AND issuer
	for i := range p.Users {
		// Search to see if the current user already has an entry that matches on userEmail AND issuer
		user := &p.Users[i]
		if user.IdentityAttribute == userEmail && user.Issuer == issuer {
			if firstMatchingEntry == nil {
				firstMatchingEntry = user
			}
			for _, p := range user.Principals {
				if p == principal {
					// If we find an entry that matches on userEmail AND issuer AND principal, nothing to add
					log.Printf("User with email %s already has access under the principal %s, skipping...\n", userEmail, principal)
					return // return early, attempting to add a duplicate policy, a policy which already exists
				}
			}
		}
	}

	if firstMatchingEntry != nil {
		// If we are here, then we found an entry where userEmail and user.Issuer match, but not the principal.
		// Add the principal to that entries list of principals
		firstMatchingEntry.Principals = append(firstMatchingEntry.Principals, principal)
		log.Printf("Successfully added user with email %s with principal %s to the policy file\n", userEmail, principal)
		return // Done, we added the principal to the existing user
	}

	// If we are here, then there is no row in the policy file that matches
	// the userEmail and issuer.
	newUser := User{
		IdentityAttribute: userEmail,
		Principals:        []string{principal},
		Issuer:            issuer,
	}
	// Add the new user to the list of users in the policy
	p.Users = append(p.Users, newUser)
	log.Printf("Successfully added user with email %s with principal %s to the policy file\n", userEmail, principal)
}

// ToTable encodes the policy into a whitespace delimited table
func (p *Policy) ToTable() ([]byte, error) {
	table := files.Table{}
	for _, user := range p.Users {
		for _, principal := range user.Principals {
			table.AddRow(principal, user.IdentityAttribute, user.Issuer)
		}
	}
	return table.ToBytes(), nil
}

// Source declares the minimal interface to describe the source of a fetched
// opkssh policy (i.e. where the policy is retrieved from)
type Source interface {
	// Source returns a string describing the source of an opkssh policy. The
	// returned value is empty if there is no information about its source
	Source() string
}

var _ Source = &EmptySource{}

// EmptySource implements policy.Source and returns an empty string as the
// source
type EmptySource struct{}

func (EmptySource) Source() string { return "" }

// Loader declares the minimal interface to retrieve an opkssh policy from an
// arbitrary source
type Loader interface {
	// Load fetches an opkssh policy and returns information describing its
	// source. If an error occurs, all return values are nil except the error
	// value
	Load() (*Policy, Source, error)
}
