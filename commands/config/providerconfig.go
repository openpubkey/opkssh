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

package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/openpubkey/openpubkey/providers"
	"gopkg.in/yaml.v3"
)

const (
	WEBCHOOSER_ALIAS        = "WEBCHOOSER"
	OPKSSH_DEFAULT_ENVVAR   = "OPKSSH_DEFAULT"
	OPKSSH_PROVIDERS_ENVVAR = "OPKSSH_PROVIDERS"
)

type ProviderConfig struct {
	AliasList    []string `yaml:"alias"`
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret,omitempty"`
	Scopes       []string `yaml:"scopes"`
	AccessType   string   `yaml:"access_type,omitempty"`
	Prompt       string   `yaml:"prompt,omitempty"`
	RedirectURIs []string `yaml:"redirect_uris"`
	// Optional field to enable the use of non-localhost redirect URI.
	// This is an advanced option for embedding opkssh in server-side
	// logic and should not be specified most of the time.
	RemoteRedirectURI string `yaml:"remote_redirect_uri,omitempty"`
	SendAccessToken   bool   `yaml:"send_access_token,omitempty"`
}

func (p *ProviderConfig) UnmarshalYAML(value *yaml.Node) error {

	// We use tmp to handle lists as space-separated strings, e.g., scope: openid profile email offline_access.
	var tmp struct {
		AliasList    string   `yaml:"alias"`
		Issuer       string   `yaml:"issuer"`
		ClientID     string   `yaml:"client_id"`
		ClientSecret string   `yaml:"client_secret"`
		Scopes       string   `yaml:"scopes"`
		AccessType   string   `yaml:"access_type"`
		Prompt       string   `yaml:"prompt"`
		RedirectURIs []string `yaml:"redirect_uris"`
		// Optional field to enable the use of non-localhost redirect URI.
		// This is an advanced option for embedding opkssh in server-side
		// logic and should not be specified most of the time.
		RemoteRedirectURI string `yaml:"remote_redirect_uri,omitempty"`
		SendAccessToken   bool   `yaml:"send_access_token,omitempty"`
	}

	// Set default values
	tmp.Scopes = "openid profile email"
	tmp.AccessType = "offline"
	tmp.Prompt = "consent"
	tmp.RedirectURIs = []string{
		"http://localhost:3000/login-callback",
		"http://localhost:10001/login-callback",
		"http://localhost:11110/login-callback",
	}

	if err := value.Decode(&tmp); err != nil {
		return err
	}
	*p = ProviderConfig{
		AliasList:         strings.Fields(tmp.AliasList),
		Issuer:            tmp.Issuer,
		ClientID:          tmp.ClientID,
		ClientSecret:      tmp.ClientSecret,
		Scopes:            strings.Fields(tmp.Scopes),
		AccessType:        tmp.AccessType,
		Prompt:            tmp.Prompt,
		RedirectURIs:      tmp.RedirectURIs,
		RemoteRedirectURI: tmp.RemoteRedirectURI,
		SendAccessToken:   tmp.SendAccessToken,
	}
	return nil
}

// TODO: Move this into OpenPubkey providers package
func DefaultProviderConfig() ProviderConfig {
	return ProviderConfig{
		AliasList:    []string{},
		Issuer:       "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{"openid", "email"},
		AccessType:   "offline",
		RedirectURIs: []string{
			"http://localhost:3000/login-callback",
			"http://localhost:10001/login-callback",
			"http://localhost:11110/login-callback",
		},
		Prompt: "consent",
	}
}

func GitHubProviderConfig() ProviderConfig {
	return ProviderConfig{
		AliasList: []string{"github"},
		Issuer:    "https://token.actions.githubusercontent.com",
		// This is required, but is not used for this provider.
		ClientID: "unused",
	}
}

// NewProviderConfigFromString is a function to create the provider config from a string of the format
// {alias},{provider_url},{client_id},{client_secret},{scopes}
func NewProviderConfigFromString(configStr string, hasAlias bool) (ProviderConfig, error) {
	parts := strings.Split(configStr, ",")
	alias := ""
	if hasAlias {
		// If the config string has an alias, we need to remove it from the parts
		alias = parts[0]
		parts = parts[1:]
	}
	if len(parts) < 2 {
		if hasAlias {
			return ProviderConfig{}, fmt.Errorf("invalid provider config string. Expected format <alias>,<issuer>,<client_id> or <alias>,<issuer>,<client_id>,<client_secret> or <alias>,<issuer>,<client_id>,<client_secret>,<scopes>")
		}
		return ProviderConfig{}, fmt.Errorf("invalid provider config string. Expected format <issuer>,<client_id> or <issuer>,<client_id>,<client_secret> or <issuer>,<client_id>,<client_secret>,<scopes>")
	}

	providerConfig := DefaultProviderConfig()
	providerConfig.AliasList = []string{alias}
	providerConfig.Issuer = parts[0]
	providerConfig.ClientID = parts[1]

	if providerConfig.ClientID == "" {
		return ProviderConfig{}, fmt.Errorf("invalid provider client-ID value got (%s)", providerConfig.ClientID)
	}

	if len(parts) > 2 {
		providerConfig.ClientSecret = parts[2]
	} else {
		providerConfig.ClientSecret = ""
	}

	if len(parts) > 3 {
		providerConfig.Scopes = strings.Split(parts[3], " ")
	} else {
		providerConfig.Scopes = []string{"openid", "email"}
	}

	if strings.HasPrefix(providerConfig.Issuer, "https://accounts.google.com") {
		// The Google OP is strange in that it requires a client secret even if this is a public OIDC App.
		// Despite its name the Google OP client secret is a public value.
		if providerConfig.ClientSecret == "" {
			if hasAlias {
				return ProviderConfig{}, fmt.Errorf("invalid provider argument format. Expected format for google: <alias>,<issuer>,<client_id>,<client_secret>")
			} else {
				return ProviderConfig{}, fmt.Errorf("invalid provider argument format. Expected format for google: <issuer>,<client_id>,<client_secret>")
			}
		}
	}
	return providerConfig, nil
}

// NewProviderFromConfig is a function to create the provider from the config
func (p *ProviderConfig) ToProvider(openBrowser bool) (providers.OpenIdProvider, error) {
	if p.Issuer == "" {
		return nil, fmt.Errorf("invalid provider issuer value got (%s)", p.Issuer)
	}

	if !strings.HasPrefix(p.Issuer, "https://") {
		return nil, fmt.Errorf("invalid provider issuer value. Expected issuer to start with 'https://' got (%s)", p.Issuer)
	}

	if p.ClientID == "" {
		return nil, fmt.Errorf("invalid provider client-ID value got (%s)", p.ClientID)
	}
	var provider providers.OpenIdProvider

	if strings.HasPrefix(p.Issuer, "https://accounts.google.com") {
		opts := providers.GetDefaultGoogleOpOptions()
		opts.Issuer = p.Issuer
		opts.ClientID = p.ClientID
		opts.ClientSecret = p.ClientSecret
		opts.GQSign = false
		if p.hasScopes() {
			opts.Scopes = p.Scopes
		}
		opts.PromptType = p.Prompt
		opts.AccessType = p.AccessType
		opts.RedirectURIs = p.RedirectURIs
		opts.RemoteRedirectURI = p.RemoteRedirectURI
		opts.OpenBrowser = openBrowser
		provider = providers.NewGoogleOpWithOptions(opts)
	} else if strings.HasPrefix(p.Issuer, "https://login.microsoftonline.com") {
		opts := providers.GetDefaultAzureOpOptions()
		opts.Issuer = p.Issuer
		opts.ClientID = p.ClientID
		opts.GQSign = false
		if p.hasScopes() {
			opts.Scopes = p.Scopes
		}
		opts.PromptType = p.Prompt
		opts.AccessType = p.AccessType
		opts.RedirectURIs = p.RedirectURIs
		opts.RemoteRedirectURI = p.RemoteRedirectURI
		opts.OpenBrowser = openBrowser
		provider = providers.NewAzureOpWithOptions(opts)
	} else if strings.HasPrefix(p.Issuer, "https://gitlab.com") {
		opts := providers.GetDefaultGitlabOpOptions()
		opts.Issuer = p.Issuer
		opts.ClientID = p.ClientID
		opts.GQSign = false
		if p.hasScopes() {
			opts.Scopes = p.Scopes
		}
		opts.PromptType = p.Prompt
		opts.AccessType = p.AccessType
		opts.RedirectURIs = p.RedirectURIs
		opts.RemoteRedirectURI = p.RemoteRedirectURI
		opts.OpenBrowser = openBrowser
		provider = providers.NewGitlabOpWithOptions(opts)
	} else if p.Issuer == "https://issuer.hello.coop" {
		opts := providers.GetDefaultHelloOpOptions()
		opts.Issuer = p.Issuer
		opts.ClientID = p.ClientID
		opts.GQSign = false
		if p.hasScopes() {
			opts.Scopes = p.Scopes
		}
		opts.PromptType = p.Prompt
		opts.AccessType = p.AccessType
		opts.RedirectURIs = p.RedirectURIs
		opts.RemoteRedirectURI = p.RemoteRedirectURI
		opts.OpenBrowser = openBrowser
		provider = providers.NewHelloOpWithOptions(opts)
	} else if strings.HasPrefix(p.Issuer, "https://token.actions.githubusercontent.com") {
		githubOp, err := providers.NewGithubOpFromEnvironment()
		if err != nil {
			return nil, fmt.Errorf("error creating github op: %w", err)
		}
		provider = githubOp
	} else {
		// Generic provider
		opts := providers.GetDefaultStandardOpOptions(p.Issuer, p.ClientID)
		opts.ClientSecret = p.ClientSecret
		opts.PromptType = p.Prompt
		opts.AccessType = p.AccessType
		opts.RedirectURIs = p.RedirectURIs
		opts.RemoteRedirectURI = p.RemoteRedirectURI
		opts.GQSign = false
		if p.hasScopes() {
			opts.Scopes = p.Scopes
		}
		opts.OpenBrowser = openBrowser
		provider = providers.NewStandardOpWithOptions(opts)
	}

	return provider, nil
}

func (p *ProviderConfig) hasScopes() bool {
	return len(p.Scopes) > 0 && (len(p.Scopes) > 1 || p.Scopes[0] != "")
}

// GetProvidersConfigFromEnv is a function to retrieve the config from the env variables
// OPKSSH_DEFAULT can be set to an alias
// OPKSSH_PROVIDERS is a ; separated list of providers of the format <alias>,<issuer>,<client_id>,<client_secret>,<scopes>;<alias>,<issuer>,<client_id>,<client_secret>,<scopes>
func GetProvidersConfigFromEnv() ([]ProviderConfig, error) {
	// Get the providers from the env variable
	providerList, ok := os.LookupEnv(OPKSSH_PROVIDERS_ENVVAR)
	if !ok || providerList == "" {
		return nil, nil
	}
	if providerConfigList, err := ProvidersConfigListFromStrings(providerList); err != nil {
		return nil, fmt.Errorf("error getting provider config from env: %w", err)
	} else {
		return providerConfigList, nil
	}
}

func ProvidersConfigListFromStrings(providerList string) ([]ProviderConfig, error) {
	providerConfigList := make([]ProviderConfig, 0)
	for _, providerStr := range strings.Split(providerList, ";") {
		providerConfig, err := NewProviderConfigFromString(providerStr, true)
		if err != nil {
			return nil, fmt.Errorf("error parsing provider config string: %w", err)
		}
		providerConfigList = append(providerConfigList, providerConfig)
	}
	return providerConfigList, nil
}

func CreateProvidersMap(providerConfigList []ProviderConfig) (map[string]ProviderConfig, error) {
	providersConfig := make(map[string]ProviderConfig)
	for _, providerConfig := range providerConfigList {
		for _, alias := range providerConfig.AliasList {
			// If alias already exists, return an error
			if _, ok := providersConfig[alias]; ok {
				return nil, fmt.Errorf("duplicate provider alias found: %s", alias)
			}
			providersConfig[alias] = providerConfig
		}
	}
	return providersConfig, nil
}
