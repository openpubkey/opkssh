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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
)

type ProvidersRow struct {
	Issuer           string
	ClientID         string
	ExpirationPolicy string
}

func (p ProvidersRow) GetExpirationPolicy() (verifier.ExpirationPolicy, error) {
	switch p.ExpirationPolicy {
	case "12h":
		return verifier.ExpirationPolicies.MAX_AGE_12HOURS, nil
	case "24h":
		return verifier.ExpirationPolicies.MAX_AGE_24HOURS, nil
	case "48h":
		return verifier.ExpirationPolicies.MAX_AGE_48HOURS, nil
	case "1week":
		return verifier.ExpirationPolicies.MAX_AGE_1WEEK, nil
	case "oidc":
		return verifier.ExpirationPolicies.OIDC, nil
	case "oidc_refreshed":
		return verifier.ExpirationPolicies.OIDC_REFRESHED, nil
	case "never":
		return verifier.ExpirationPolicies.NEVER_EXPIRE, nil
	default:
		return verifier.ExpirationPolicy{}, fmt.Errorf("invalid expiration policy: %s", p.ExpirationPolicy)
	}
}

func (p ProvidersRow) ToString() string {
	return p.Issuer + " " + p.ClientID + " " + p.ExpirationPolicy
}

type ProviderPolicy struct {
	rows []ProvidersRow
}

func (p *ProviderPolicy) AddRow(row ProvidersRow) {
	p.rows = append(p.rows, row)
}

func (p *ProviderPolicy) GetRows() []ProvidersRow {
	return p.rows
}

// providerVerifierFromRow selects the OP verifier to use for a row in the
// providers file. The OP type is determined by the configured issuer alone,
// never by anything in the token being verified.
func providerVerifierFromRow(row ProvidersRow, cacheCfg discover.DiscoveryCacheConfig) verifier.ProviderVerifier {
	// TODO: We should handle this issuer matching in a more generic way
	// oidc.local and localhost: are a test issuers
	if row.Issuer == "https://accounts.google.com" ||
		strings.HasPrefix(row.Issuer, "http://oidc.local") ||
		strings.HasPrefix(row.Issuer, "http://localhost:") {

		opts := providers.GetDefaultGoogleOpOptions()
		opts.Issuer = row.Issuer
		opts.ClientID = row.ClientID
		opts.CacheConfig = cacheCfg
		return providers.NewGoogleOpWithOptions(opts)
	} else if strings.HasPrefix(row.Issuer, "https://login.microsoftonline.com") {
		opts := providers.GetDefaultAzureOpOptions()
		opts.Issuer = row.Issuer
		opts.ClientID = row.ClientID
		opts.CacheConfig = cacheCfg
		return providers.NewAzureOpWithOptions(opts)
	} else if row.Issuer == "https://token.actions.githubusercontent.com" {
		return cachedActionsProviderVerifier{issuer: row.Issuer, publicKeyFinder: newCachedPublicKeyFinder(cacheCfg)}
	} else if providers.IsForgejoIssuer(row.Issuer) {
		return cachedActionsProviderVerifier{issuer: strings.TrimSuffix(row.Issuer, "/"), publicKeyFinder: newCachedPublicKeyFinder(cacheCfg)}
	} else if strings.HasPrefix(row.ClientID, "OPENPUBKEY-PKTOKEN:GITLAB-CI:") {
		// Do the gitlab checks last so that github or forgejo issuers
		// checks happen first. This is to avoid a case where someone has
		// a github issuer but sets the client ID prefix to "OPENPUBKEY-PKTOKEN:GITLAB-CI:"
		return gitLabCiProviderVerifier{
			issuer:          row.Issuer,
			audience:        row.ClientID,
			publicKeyFinder: newCachedPublicKeyFinder(cacheCfg),
		}
	} else if row.Issuer == "https://gitlab.com" {
		opts := providers.GetDefaultGitlabOpOptions()
		opts.Issuer = row.Issuer
		opts.ClientID = row.ClientID
		opts.CacheConfig = cacheCfg
		return providers.NewGitlabOpWithOptions(opts)
	}

	opts := providers.GetDefaultGoogleOpOptions()
	opts.Issuer = row.Issuer
	opts.ClientID = row.ClientID
	opts.CacheConfig = cacheCfg
	return providers.NewGoogleOpWithOptions(opts)
}

func (p *ProviderPolicy) CreateVerifier(cacheCfg discover.DiscoveryCacheConfig) (*verifier.Verifier, error) {
	pvs := []verifier.ProviderVerifier{}
	var expirationPolicy verifier.ExpirationPolicy
	var err error
	for _, row := range p.rows {
		provider := providerVerifierFromRow(row, cacheCfg)

		expirationPolicy, err = row.GetExpirationPolicy()
		if err != nil {
			return nil, err
		}
		pv := verifier.ProviderVerifierExpires{
			ProviderVerifier: provider,
			Expiration:       expirationPolicy,
		}
		pvs = append(pvs, pv)
	}

	if len(pvs) == 0 {
		return nil, fmt.Errorf("no providers configured")
	}
	pktVerifier, err := verifier.NewFromMany(
		pvs,
		verifier.WithExpirationPolicy(expirationPolicy),
	)
	if err != nil {
		return nil, err
	}
	return pktVerifier, nil
}

type gitLabCiProviderVerifier struct {
	issuer          string
	audience        string
	publicKeyFinder *discover.PublicKeyFinder
}

func (g gitLabCiProviderVerifier) Issuer() string {
	return g.issuer
}

func (g gitLabCiProviderVerifier) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	if err := verifyGitLabCiTokenClaims(idt, g.audience); err != nil {
		return err
	}
	return providers.NewProviderVerifier(g.issuer, providers.ProviderVerifierOpts{
		CommitType:        providers.CommitTypesEnum.GQ_BOUND,
		DiscoverPublicKey: g.publicKeyFinder,
		GQOnly:            true,
		SkipClientIDCheck: true,
	}).VerifyIDToken(ctx, idt, cic)
}

// cachedActionsProviderVerifier preserves the GitHub Actions and Forgejo
// aud-as-commitment verification rules while using the configured persistent
// JWKS cache. The upstream constructors currently expose no cache option.
type cachedActionsProviderVerifier struct {
	issuer          string
	publicKeyFinder *discover.PublicKeyFinder
}

func (p cachedActionsProviderVerifier) Issuer() string {
	return p.issuer
}

func (p cachedActionsProviderVerifier) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	return providers.NewProviderVerifier(p.issuer, providers.ProviderVerifierOpts{
		CommitType:        providers.CommitTypesEnum.AUD_CLAIM,
		DiscoverPublicKey: p.publicKeyFinder,
		GQOnly:            true,
		SkipClientIDCheck: true,
	}).VerifyIDToken(ctx, idt, cic)
}

func newCachedPublicKeyFinder(cacheCfg discover.DiscoveryCacheConfig) *discover.PublicKeyFinder {
	return &discover.PublicKeyFinder{
		JwksFunc: func(ctx context.Context, issuer string) ([]byte, error) {
			return discover.GetJwksByIssuer(ctx, issuer, nil)
		},
		CacheConfig: cacheCfg,
	}
}

func verifyGitLabCiTokenClaims(idt []byte, audience string) error {
	claims, err := decodeJwtPayload(idt)
	if err != nil {
		return err
	}

	if !audienceMatches(claims["aud"], audience) {
		return fmt.Errorf("gitlab-ci token audience does not match expected audience %q", audience)
	}

	for _, claimName := range []string{"ci_config_ref_uri", "job_id", "job_project_path", "pipeline_id"} {
		if !claimIsPresent(claims[claimName]) {
			return fmt.Errorf("gitlab-ci token missing required claim %q", claimName)
		}
	}
	return nil
}

func decodeJwtPayload(idt []byte) (map[string]any, error) {
	parts := strings.Split(string(idt), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid jwt: expected at least two parts")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("error decoding jwt payload: %w", err)
		}
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("error unmarshalling jwt payload: %w", err)
	}
	return claims, nil
}

func audienceMatches(rawAudience any, expectedAudience string) bool {
	switch audience := rawAudience.(type) {
	case string:
		return audience == expectedAudience
	case []any:
		for _, value := range audience {
			if audienceValue, ok := value.(string); ok && audienceValue == expectedAudience {
				return true
			}
		}
	}
	return false
}

func claimIsPresent(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case string:
		return v != ""
	case []any:
		return len(v) > 0
	default:
		return true
	}
}

func (p ProviderPolicy) ToString() string {
	var sb strings.Builder
	for _, row := range p.rows {
		sb.WriteString(row.ToString() + "\n")
	}
	return sb.String()
}

// ProviderLoader defines the interface for loading provider policies
type ProviderLoader interface {
	LoadProviderPolicy(path string) (*ProviderPolicy, error)
}

type ProvidersFileLoader struct {
	files.FileLoader
	Path string
}

func NewProviderFileLoader() *ProvidersFileLoader {
	return &ProvidersFileLoader{
		FileLoader: files.FileLoader{
			Fs:           afero.NewOsFs(),
			RequiredPerm: files.ModeSystemPerms,
		},
	}
}

func (o *ProvidersFileLoader) LoadProviderPolicy(path string) (*ProviderPolicy, error) {
	content, err := o.LoadFileAtPath(path)
	if err != nil {
		return nil, err
	}
	policy := o.FromTable(content, path)
	return policy, nil
}

// FromTable decodes whitespace delimited input into policy.Policy
func (o ProvidersFileLoader) ToTable(opPolicies ProviderPolicy) files.Table {
	table := files.Table{}
	for _, opPolicy := range opPolicies.rows {
		table.AddRow(opPolicy.Issuer, opPolicy.ClientID, opPolicy.ExpirationPolicy)
	}
	return table
}

// FromTable decodes whitespace delimited input into policy.Policy
// Path is passed only for logging purposes
func (o *ProvidersFileLoader) FromTable(input []byte, path string) *ProviderPolicy {
	table := files.NewTable(input)
	policy := &ProviderPolicy{
		rows: []ProvidersRow{},
	}
	for _, row := range table.GetRows() {
		// Error should not break everyone's ability to login, skip those rows
		if len(row) != 3 {
			configProblem := files.ConfigProblem{
				Filepath:      path,
				OffendingLine: strings.Join(row, " "),
				ErrorMessage:  fmt.Sprintf("wrong number of arguments (expected=3, got=%d)", len(row)),
				Source:        "providers policy file",
			}
			files.ConfigProblems().RecordProblem(configProblem)
			continue
		}
		policyRow := ProvidersRow{
			Issuer:           row[0],
			ClientID:         row[1],
			ExpirationPolicy: row[2], // TODO: Validate this so that we can determine the line number that has the error
		}
		policy.AddRow(policyRow)
	}
	return policy
}
