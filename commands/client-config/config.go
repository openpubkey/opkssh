package config

import (
	_ "embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed default-client-config.yml
var defaultClientConfig []byte

type ClientConfig struct {
	DefaultProvider string           `yaml:"default_provider"`
	Providers       []ProviderConfig `yaml:"providers"`
}

func NewClientConfig(c []byte) (*ClientConfig, error) {
	var config ClientConfig
	if err := yaml.Unmarshal(c, &config); err != nil {
		return nil, err
	}

	// fmt.Printf("Default Provider: %s\n\n", config.DefaultProvider)
	// for _, p := range config.Providers {
	// 	fmt.Printf("Aliases: %v\nIssuer: %s\nScopes: %v\nAccessType: %s\nPrompt: %s\n\n",
	// 		p.Alias, p.Issuer, p.Scopes, p.AccessType, p.Prompt)
	// }
	return &config, nil
}

func DefaultClientConfig() (*ClientConfig, error) {
	return NewClientConfig(defaultClientConfig)
}

func (c *ClientConfig) GetProvidersStr() (string, error) {
	if len(c.Providers) == 0 {
		return "", fmt.Errorf("no providers found")
	}
	var providers []string
	for _, p := range c.Providers {
		providerStr := fmt.Sprintf("%s,%s,%s,%s,%s", p.Alias, p.Issuer, p.ClientID, p.ClientSecret, p.Scopes)
		providers = append(providers, providerStr)
	}
	return strings.Join(providers, ";"), nil

}

type ProviderConfig struct {
	Alias        []string `yaml:"alias"`
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret,omitempty"`
	Scopes       []string `yaml:"scopes"`
	AccessType   string   `yaml:"access_type,omitempty"`
	Prompt       string   `yaml:"prompt,omitempty"`
	RedirectURIs []string `yaml:"redirect_uris"`
}

func (p *ProviderConfig) UnmarshalYAML(value *yaml.Node) error {
	var tmp struct {
		Alias        string   `yaml:"alias"`
		Issuer       string   `yaml:"issuer"`
		ClientID     string   `yaml:"client_id"`
		ClientSecret string   `yaml:"client_secret"`
		Scopes       string   `yaml:"scopes"`
		AccessType   string   `yaml:"access_type"`
		Prompt       string   `yaml:"prompt"`
		RedirectURIs []string `yaml:"redirect_uris"`
	}
	if err := value.Decode(&tmp); err != nil {
		return err
	}
	*p = ProviderConfig{
		Alias:        strings.Fields(tmp.Alias),
		Issuer:       tmp.Issuer,
		ClientID:     tmp.ClientID,
		ClientSecret: tmp.ClientSecret,
		Scopes:       strings.Fields(tmp.Scopes),
		AccessType:   tmp.AccessType,
		Prompt:       tmp.Prompt,
		RedirectURIs: tmp.RedirectURIs,
	}
	return nil
}
