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
	// EmailOrSub is either the user's email or the user's subscriber ID. It is
	// the expected value used when comparing against an id_token's email claim
	// Subscriber ID is a unique identifier for the user at the OpenID Provider
	EmailOrSub string
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

// FromTable decodes whitespace delimited input into policy.Policy
func FromTable(input []byte, path string) *Policy {
	table := files.NewTable(input)
	policy := &Policy{}
	for i, row := range table.GetRows() {
		// Error should not break everyone's ability to login, skip those rows
		if len(row) != 3 {
			configProblem := files.ConfigProblem{
				Filepath:            path,
				OffendingLine:       strings.Join(row, " "),
				OffendingLineNumber: i,
				ErrorMessage:        fmt.Sprintf("wrong number of arguments (expected=3, got=%d)", len(row)),
				Source:              "user policy file",
			}
			files.ConfigProblems().RecordProblem(configProblem)
			continue
		}
		user := User{
			Principals: []string{row[0]},
			EmailOrSub: row[1],
			Issuer:     row[2],
		}
		policy.Users = append(policy.Users, user)
	}
	return policy
}

// AddAllowedPrincipal adds a new allowed principal to the user whose email is
// equal to userEmail. If no user can be found with the email userEmail, then a
// new user entry is added with an initial allowed principals list containing
// principal. No changes are made if the principal is already allowed for this
// user.
func (p *Policy) AddAllowedPrincipal(principal string, userEmail string, issuer string) {
	userExists := false
	if len(p.Users) != 0 {
		// search to see if the current user already has an entry in the policy
		// file
		for i := range p.Users {
			user := &p.Users[i]
			if user.EmailOrSub == userEmail && user.Issuer == issuer {
				principalExists := false
				for _, p := range user.Principals {
					// if the principal already exists for this user, then skip
					if p == principal {
						log.Printf("User with email %s already has access under the principal %s, skipping...\n", userEmail, principal)
						principalExists = true
					}
				}

				if !principalExists {
					user.Principals = append(user.Principals, principal)
					user.Issuer = issuer
					log.Printf("Successfully added user with email %s with principal %s to the policy file\n", userEmail, principal)
				}
				userExists = true
			}
		}
	}

	// if the policy is empty or if no user found with userEmail, then create a
	// new entry
	if len(p.Users) == 0 || !userExists {
		newUser := User{
			EmailOrSub: userEmail,
			Principals: []string{principal},
			Issuer:     issuer,
		}
		// add the new user to the list of users in the policy
		p.Users = append(p.Users, newUser)
	}
}

// ToTable encodes the policy into a whitespace delimited table
func (p *Policy) ToTable() ([]byte, error) {
	table := files.Table{}
	for _, user := range p.Users {
		for _, principal := range user.Principals {
			table.AddRow(principal, user.EmailOrSub, user.Issuer)
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
