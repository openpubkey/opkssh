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

package commands

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/choosers"
	"github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
	"github.com/openpubkey/opkssh/commands/config"
	"github.com/openpubkey/opkssh/sshcert"
	"github.com/spf13/afero"
	"golang.org/x/crypto/ssh"
)

type LoginCmd struct {
	// Inputs
	Fs                    afero.Fs
	AutoRefreshArg        bool
	ConfigPathArg         string
	CreateConfigArg       bool
	ConfigureArg          bool
	LogDirArg             string
	SendAccessTokenArg    bool
	DisableBrowserOpenArg bool
	PrintIdTokenArg       bool
	KeyPathArg            string
	ProviderArg           string
	ProviderAliasArg      string
	SSHConfigured         bool
	Verbosity             int                       // Default verbosity is 0, 1 is verbose, 2 is debug
	overrideProvider      *providers.OpenIdProvider // Used in tests to override the provider to inject a mock provider

	// State
	Config *config.ClientConfig

	// Outputs
	pkt        *pktoken.PKToken
	signer     crypto.Signer
	alg        jwa.SignatureAlgorithm
	client     *client.OpkClient
	principals []string
}

func NewLogin(autoRefreshArg bool, configPathArg string, createConfigArg bool, configureArg bool, logDirArg string,
	sendAccessTokenArg bool, disableBrowserOpenArg bool, printIdTokenArg bool,
	providerArg string, keyPathArg string, providerAliasArg string,
) *LoginCmd {
	return &LoginCmd{
		Fs:                    afero.NewOsFs(),
		AutoRefreshArg:        autoRefreshArg,
		ConfigPathArg:         configPathArg,
		CreateConfigArg:       createConfigArg,
		ConfigureArg:          configureArg,
		LogDirArg:             logDirArg,
		SendAccessTokenArg:    sendAccessTokenArg,
		DisableBrowserOpenArg: disableBrowserOpenArg,
		PrintIdTokenArg:       printIdTokenArg,
		KeyPathArg:            keyPathArg,
		ProviderArg:           providerArg,
		ProviderAliasArg:      providerAliasArg,
	}
}

func (l *LoginCmd) Run(ctx context.Context) error {
	// If a log directory was provided, write any logs to a file in that directory AND stdout
	if l.LogDirArg != "" {
		logFilePath := filepath.Join(l.LogDirArg, "opkssh.log")
		logFile, err := l.Fs.OpenFile(logFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o660)
		if err != nil {
			log.Printf("Failed to open log for writing: %v \n", err)
		}
		defer logFile.Close()
		multiWriter := io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(multiWriter)
	} else {
		log.SetOutput(os.Stdout)
	}

	if l.Verbosity >= 2 {
		log.Printf("DEBUG: running login command with args: %+v", *l)
	}

	// If the Config has been set in the struct don't replace it. This is useful for testing
	if l.Config == nil {
		if l.ConfigPathArg == "" {
			dir, dirErr := os.UserHomeDir()
			if dirErr != nil {
				return fmt.Errorf("failed to get user config dir: %w", dirErr)
			}
			l.ConfigPathArg = filepath.Join(dir, ".opk", "config.yml")
		}
		var configBytes []byte
		if _, err := l.Fs.Stat(l.ConfigPathArg); err == nil {
			if l.CreateConfigArg {
				log.Printf("--create-config=true but config file already exists at %s", l.ConfigPathArg)
			}

			// Load the file from the filesystem
			afs := &afero.Afero{Fs: l.Fs}
			configBytes, err = afs.ReadFile(l.ConfigPathArg)
			if err != nil {
				return fmt.Errorf("failed to read config file: %w", err)
			}
			l.Config, err = config.NewClientConfig(configBytes)
			if err != nil {
				return fmt.Errorf("failed to parse config file: %w", err)
			}
		} else {
			if l.CreateConfigArg {
				afs := &afero.Afero{Fs: l.Fs}
				if err := l.Fs.MkdirAll(filepath.Dir(l.ConfigPathArg), 0o755); err != nil {
					return fmt.Errorf("failed to create config directory: %w", err)
				}
				if err := afs.WriteFile(l.ConfigPathArg, config.DefaultClientConfig, 0o644); err != nil {
					return fmt.Errorf("failed to write default config file: %w", err)
				}
				log.Printf("created client config file at %s", l.ConfigPathArg)
				return nil
			} else {
				log.Printf("failed to find client config file to generate a default config, run `opkssh login --create-config` to create a default config file")
			}
			l.Config, err = config.NewClientConfig(config.DefaultClientConfig)
			if err != nil {
				return fmt.Errorf("failed to parse default config file: %w", err)
			}
		}
	}

	if l.ConfigureArg {
		err := l.configureSSH()
		if err != nil {
			return fmt.Errorf("failed to configure SSH: %w", err)
		}
		return nil
	} else {
		l.checkSSHConfigured()
	}

	if isGitHubEnvironment() {
		l.Config.Providers = append(l.Config.Providers, config.GitHubProviderConfig())
	}

	var provider providers.OpenIdProvider
	if l.overrideProvider != nil {
		provider = *l.overrideProvider
	} else {
		op, chooser, err := l.determineProvider()
		if err != nil {
			return err
		}
		if chooser != nil {
			provider, err = chooser.ChooseOp(ctx)
			if err != nil {
				return fmt.Errorf("error choosing provider: %w", err)
			}
		} else if op != nil {
			provider = op
		} else {
			return fmt.Errorf("no provider found") // Either the provider or the chooser must be set. If this occurs we have a bug in the code.
		}
	}

	// This arg is true if set, so if it false it hasn't been set and
	// we should use the config value for the matching providing.
	// If it is true we ignore the config
	if !l.SendAccessTokenArg {
		if opConfig, ok := l.Config.GetByIssuer(provider.Issuer()); !ok {
			// This can happen if the provider is supplied via the command line or environment variables and thus not in the config
			log.Printf("Warning: could not find issuer %s in client config providers\n", provider.Issuer())
		} else {
			l.SendAccessTokenArg = opConfig.SendAccessToken
		}
	}

	// Execute login command
	if l.AutoRefreshArg {
		if providerRefreshable, ok := provider.(providers.RefreshableOpenIdProvider); ok {
			err := l.LoginWithRefresh(ctx, providerRefreshable, l.PrintIdTokenArg, l.KeyPathArg)
			if err != nil {
				return fmt.Errorf("error logging in: %w", err)
			}
		} else {
			return fmt.Errorf("supplied OpenID Provider (%v) does not support auto-refresh and auto-refresh argument set to true", provider.Issuer())
		}
	} else {
		err := l.Login(ctx, provider, l.PrintIdTokenArg, l.KeyPathArg)
		if err != nil {
			return fmt.Errorf("error logging in: %w", err)
		}
	}
	return nil
}

func (l *LoginCmd) configureSSH() error {

	userhomeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user config dir: %v", err)
	}

	const includeDirective = "Include ~/.ssh/opkssh/config"
	const opkSshDir = ".ssh/opkssh"
	var userSshConfig = filepath.Join(userhomeDir, ".ssh/config")
	var userOpkSshDir = filepath.Join(userhomeDir, opkSshDir)
	var userOpkSshConfig = filepath.Join(userOpkSshDir, "config")

	if _, err := l.Fs.Stat(userOpkSshConfig); err == nil {
		log.Println("--configure but already configured")
	}

	log.Printf("Creating config directory at %s", userOpkSshDir)

	afs := &afero.Afero{Fs: l.Fs}
	err = afs.MkdirAll(userOpkSshDir, 0o0700)
	if err != nil {
		return fmt.Errorf("failed to create opkssh SSH directory: %w", err)
	}

	log.Printf("Creating config file at %s", userOpkSshConfig)

	file, err := afs.OpenFile(userOpkSshConfig, os.O_CREATE, 0o0600)
	if err != nil {
		return fmt.Errorf("failed to create opkssh SSH directory: %w", err)
	}
	defer file.Close()

	log.Printf("Adding include directive to SSH config at %s", "~/.ssh/config")

	content, err := afs.ReadFile(userSshConfig)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to read SSH config file: %w", err)
	}

	if strings.Contains(string(content), includeDirective) {
		log.Println("Found include directive file in SSH config, skipping...")
	} else {
		// construct new SSH config
		content = slices.Concat([]byte(includeDirective+"\n\n"), content)

		err = afs.WriteFile(userSshConfig, content, 0o0600)
		if err != nil {
			return fmt.Errorf("failed to write SSH config file: %w", err)
		}
	}

	l.SSHConfigured = true
	log.Println("Configured SSH identity directory")
	return nil
}

func (l *LoginCmd) checkSSHConfigured() {

	userhomeDir, err := os.UserHomeDir()
	if err != nil {
		log.Printf("Failed to get user config dir: %v", err)
		return
	}

	const includeDirective = "Include ~/.ssh/opkssh/config"
	const opkSshDir = ".ssh/opkssh"
	var userSshConfig = filepath.Join(userhomeDir, ".ssh/config")
	var userOpkSshDir = filepath.Join(userhomeDir, opkSshDir)
	var userOpkSshConfig = filepath.Join(userOpkSshDir, "config")

	afs := &afero.Afero{Fs: l.Fs}

	content, err := afs.ReadFile(userSshConfig)
	if err != nil {
		// no user SSH config, could not have included ours
		return
	}

	if !strings.Contains(string(content), includeDirective) {
		// no include directive
		return
	}

	_, err = afs.Stat(userOpkSshConfig)
	if err != nil {
		// opkssh ssh config missing
		return
	}

	fmt.Println("OPK SSH identity directory is configured")

	l.SSHConfigured = true
}

func (l *LoginCmd) determineProvider() (providers.OpenIdProvider, *choosers.WebChooser, error) {
	openBrowser := !l.DisableBrowserOpenArg

	var defaultProviderAlias string
	var providerConfigs []config.ProviderConfig
	var provider providers.OpenIdProvider
	var err error

	// If the user has supplied commandline arguments for the provider, short circuit and use providerArg
	if l.ProviderArg != "" {
		providerConfig, err := config.NewProviderConfigFromString(l.ProviderArg, false)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing provider argument: %w", err)
		}

		if provider, err = providerConfig.ToProvider(openBrowser); err != nil {
			return nil, nil, fmt.Errorf("error creating provider from config: %w", err)
		} else {
			return provider, nil, nil
		}
	}

	// Set the default provider from the env variable if specified
	defaultProviderEnv, _ := os.LookupEnv(config.OPKSSH_DEFAULT_ENVVAR)
	providerConfigsEnv, err := config.GetProvidersConfigFromEnv()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting provider config from env: %w", err)
	}

	if l.ProviderAliasArg != "" {
		defaultProviderAlias = l.ProviderAliasArg
	} else if defaultProviderEnv != "" {
		defaultProviderAlias = defaultProviderEnv
	} else if l.Config.DefaultProvider != "" {
		defaultProviderAlias = l.Config.DefaultProvider
	} else {
		defaultProviderAlias = config.WEBCHOOSER_ALIAS
	}

	if providerConfigsEnv != nil {
		providerConfigs = providerConfigsEnv
	} else if len(l.Config.Providers) > 0 {
		providerConfigs = l.Config.Providers
	} else {
		return nil, nil, fmt.Errorf("no providers specified")
	}

	if strings.ToUpper(defaultProviderAlias) != config.WEBCHOOSER_ALIAS {
		providerMap, err := config.CreateProvidersMap(providerConfigs)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating provider map: %w", err)
		}
		providerConfig, ok := providerMap[defaultProviderAlias]
		if !ok {
			return nil, nil, fmt.Errorf("error getting provider config for alias %s", defaultProviderAlias)
		}
		provider, err = providerConfig.ToProvider(openBrowser)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating provider from config: %w", err)
		}
		return provider, nil, nil
	} else {
		// If the default provider is WEBCHOOSER, we need to create a chooser and return it
		var providerList []providers.BrowserOpenIdProvider
		for _, providerConfig := range providerConfigs {
			op, err := providerConfig.ToProvider(openBrowser)
			if err != nil {
				return nil, nil, fmt.Errorf("error creating provider from config: %w", err)
			}
			providerList = append(providerList, op.(providers.BrowserOpenIdProvider))
		}

		chooser := choosers.NewWebChooser(
			providerList, openBrowser,
		)
		return nil, chooser, nil
	}
}

func (l *LoginCmd) login(ctx context.Context, provider providers.OpenIdProvider, printIdToken bool, seckeyPath string) (*LoginCmd, error) {
	var err error
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}

	opkClient, err := client.New(provider, client.WithSigner(signer, alg))
	if err != nil {
		return nil, err
	}

	pkt, err := opkClient.Auth(ctx)
	if err != nil {
		return nil, err
	}

	l.pkt = pkt

	var accessToken []byte
	if l.SendAccessTokenArg {
		accessToken = opkClient.GetAccessToken()
		if accessToken == nil {
			return nil, fmt.Errorf("access token required but provider (%s) did not set access-token", opkClient.Op.Issuer())
		}
	}

	// If principals is empty the server does not enforce any principal. The OPK
	// verifier should use policy to make this decision.
	principals := []string{}
	certBytes, seckeySshPem, err := createSSHCertWithAccessToken(pkt, accessToken, signer, principals)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SSH cert: %w", err)
	}

	// Write ssh secret key and public key to filesystem
	if seckeyPath != "" {
		// If we have set seckeyPath then write it there
		if err := l.writeKeys(seckeyPath, seckeyPath+"-cert.pub", seckeySshPem, certBytes); err != nil {
			return nil, fmt.Errorf("failed to write SSH keys to filesystem: %w", err)
		}
	} else if l.SSHConfigured {
		if err := l.writeKeysToOpkSSHDir(seckeySshPem, certBytes); err != nil {
			return nil, fmt.Errorf("failed to write SSH keys to OPK SSH dir: %w", err)
		}
	} else {
		// If keyPath isn't set then write it to the default location
		if err := l.writeKeysToSSHDir(seckeySshPem, certBytes); err != nil {
			return nil, fmt.Errorf("failed to write SSH keys to filesystem: %w", err)
		}
	}

	if printIdToken {
		idTokenStr, err := PrettyIdToken(*pkt)
		if err != nil {
			return nil, fmt.Errorf("failed to format ID Token: %w", err)
		}

		fmt.Printf("id_token:\n%s\n", idTokenStr)
	}

	idStr, err := IdentityString(*pkt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ID Token: %w", err)
	}
	fmt.Printf("Keys generated for identity\n%s\n", idStr)

	return &LoginCmd{
		pkt:        pkt,
		signer:     signer,
		client:     opkClient,
		alg:        alg,
		principals: principals,
	}, nil
}

// Login performs the OIDC login procedure and creates the SSH certs/keys in the
// default SSH key location.
func (l *LoginCmd) Login(ctx context.Context, provider providers.OpenIdProvider, printIdToken bool, seckeyPath string) error {
	_, err := l.login(ctx, provider, printIdToken, seckeyPath)
	return err
}

// LoginWithRefresh performs the OIDC login procedure, creates the SSH
// certs/keys in the default SSH key location, and continues to run and refresh
// the PKT (and create new SSH certs) indefinitely as its token expires. This
// function only returns if it encounters an error or if the supplied context is
// cancelled.
func (l *LoginCmd) LoginWithRefresh(ctx context.Context, provider providers.RefreshableOpenIdProvider, printIdToken bool, seckeyPath string) error {
	if loginResult, err := l.login(ctx, provider, printIdToken, seckeyPath); err != nil {
		return err
	} else {
		var claims struct {
			Expiration int64 `json:"exp"`
		}
		if err := json.Unmarshal(loginResult.pkt.Payload, &claims); err != nil {
			return err
		}

		for {
			// Sleep until a minute before expiration to give us time to refresh
			// the token and minimize any interruptions
			untilExpired := time.Until(time.Unix(claims.Expiration, 0)) - time.Minute
			log.Printf("Waiting for %v before attempting to refresh id_token...", untilExpired)
			select {
			case <-time.After(untilExpired):
				log.Print("Refreshing id_token...")
			case <-ctx.Done():
				return ctx.Err()
			}

			refreshedPkt, err := loginResult.client.Refresh(ctx)
			if err != nil {
				return err
			}
			loginResult.pkt = refreshedPkt

			var accessToken []byte
			if l.SendAccessTokenArg {
				accessToken = loginResult.client.GetAccessToken()
				if accessToken == nil {
					return fmt.Errorf("access token required but provider (%s) did not set access-token on refresh: %w", loginResult.client.Op.Issuer(), err)
				}
			}

			certBytes, seckeySshPem, err := createSSHCertWithAccessToken(loginResult.pkt, accessToken, loginResult.signer, loginResult.principals)
			if err != nil {
				return fmt.Errorf("failed to generate SSH cert: %w", err)
			}

			// Write ssh secret key and public key to filesystem
			if seckeyPath != "" {
				// If we have set seckeyPath then write it there
				if err := l.writeKeys(seckeyPath, seckeyPath+"-cert.pub", seckeySshPem, certBytes); err != nil {
					return fmt.Errorf("failed to write SSH keys to filesystem: %w", err)
				}
			} else {
				// If keyPath isn't set then write it to the default location
				if err := l.writeKeysToSSHDir(seckeySshPem, certBytes); err != nil {
					return fmt.Errorf("failed to write SSH keys to filesystem: %w", err)
				}
			}

			comPkt, err := refreshedPkt.Compact()
			if err != nil {
				return err
			}

			payloadB64 := payloadFromCompactPkt(comPkt)
			payload, err := base64.RawURLEncoding.DecodeString(string(payloadB64))
			if err != nil {
				return fmt.Errorf("refreshed ID token payload is not base64 encoded: %w", err)
			}

			if err = json.Unmarshal(payload, &claims); err != nil {
				return fmt.Errorf("malformed refreshed ID token payload: %w", err)
			}
		}
	}
}

func createSSHCert(pkt *pktoken.PKToken, signer crypto.Signer, principals []string) ([]byte, []byte, error) {
	return createSSHCertWithAccessToken(pkt, nil, signer, principals)
}

func createSSHCertWithAccessToken(pkt *pktoken.PKToken, accessToken []byte, signer crypto.Signer, principals []string) ([]byte, []byte, error) {
	cert, err := sshcert.New(pkt, accessToken, principals)
	if err != nil {
		return nil, nil, err
	}
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, nil, err
	}

	signerMas, err := ssh.NewSignerWithAlgorithms(sshSigner.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoECDSA256})
	if err != nil {
		return nil, nil, err
	}

	sshCert, err := cert.SignCert(signerMas)
	if err != nil {
		return nil, nil, err
	}
	certBytes := ssh.MarshalAuthorizedKey(sshCert)
	// Remove newline character that MarshalAuthorizedKey() adds
	certBytes = certBytes[:len(certBytes)-1]

	seckeySsh, err := ssh.MarshalPrivateKey(signer, "openpubkey cert")
	if err != nil {
		return nil, nil, err
	}
	seckeySshBytes := pem.EncodeToMemory(seckeySsh)

	return certBytes, seckeySshBytes, nil
}

func (l *LoginCmd) writeKeysToOpkSSHDir(secKeyPem []byte, certBytes []byte) error {

	const (
		opkSshPath     = ".ssh/opkssh"
		configFileName = "config"
	)

	userhomeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	opkSshUserPath := filepath.Join(userhomeDir, opkSshPath)
	opkSshConfigPath := filepath.Join(opkSshUserPath, configFileName)

	sshKeyName := l.makeSSHKeyFileName(l.pkt)

	privKeyPath := filepath.Join(opkSshUserPath, sshKeyName)
	pubKeyPath := filepath.Join(privKeyPath + "-cert.pub")

	// get key comment
	issuer, err := l.pkt.Issuer()
	if err != nil {
		issuer = "unknown"
	}

	audience, err := l.pkt.Audience()
	if err != nil {
		audience = "unknown"
	}

	comment := " openpubkey: " + issuer + " " + audience

	// add key to config
	afs := &afero.Afero{Fs: l.Fs}
	configContent, err := afs.ReadFile(opkSshConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read opk ssh config file (%s): %w", opkSshConfigPath, err)
	}

	if !strings.Contains(string(configContent), privKeyPath) {
		configContent = slices.Concat(
			[]byte("IdentityFile "+privKeyPath+"\n"),
			configContent,
		)
	}

	err = afs.WriteFile(opkSshConfigPath, configContent, 0600)
	if err != nil {
		return fmt.Errorf("failed to write opk ssh config file (%s): %w", opkSshConfigPath, err)
	}

	// write ssh key files
	return l.writeKeysComment(privKeyPath, pubKeyPath, secKeyPem, certBytes, comment)
}

func (l *LoginCmd) writeKeysToSSHDir(seckeySshPem []byte, certBytes []byte) error {
	homePath, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	sshPath := filepath.Join(homePath, ".ssh")

	// Make ~/.ssh if folder does not exist
	err = l.Fs.MkdirAll(sshPath, os.ModePerm)
	if err != nil {
		return err
	}

	// For ssh to automatically find the key created by openpubkey when
	// connecting, we use one of the default ssh key paths. However, the file
	// might contain an existing key. We will overwrite the key if it was
	// generated by openpubkey  which we check by looking at the associated
	// comment. If the comment is equal to "openpubkey", we overwrite the file
	// with a new key.
	for _, keyFilename := range []string{"id_ecdsa", "id_ed25519"} {
		seckeyPath := filepath.Join(sshPath, keyFilename)
		pubkeyPath := seckeyPath + "-cert.pub"

		if !l.fileExists(seckeyPath) {
			// If ssh key file does not currently exist, we don't have to worry about overwriting it
			return l.writeKeys(seckeyPath, pubkeyPath, seckeySshPem, certBytes)
		} else if !l.fileExists(pubkeyPath) {
			continue
		} else {
			// If the ssh key file does exist, check if it was generated by openpubkey, if it was then it is safe to overwrite
			afs := &afero.Afero{Fs: l.Fs}
			sshPubkey, err := afs.ReadFile(pubkeyPath)
			if err != nil {
				log.Println("Failed to read:", pubkeyPath)
				continue
			}
			_, comment, _, _, err := ssh.ParseAuthorizedKey(sshPubkey)
			if err != nil {
				log.Println("Failed to parse:", pubkeyPath)
				continue
			}

			// If the key comment is "openpubkey" then we generated it
			if comment == "openpubkey" {
				return l.writeKeys(seckeyPath, pubkeyPath, seckeySshPem, certBytes)
			}
		}
	}
	return fmt.Errorf("no default ssh key file free for openpubkey")
}

func (l *LoginCmd) writeKeys(seckeyPath string, pubkeyPath string, seckeySshPem []byte, certBytes []byte) error {
	// Write ssh secret key to filesystem
	afs := &afero.Afero{Fs: l.Fs}
	if err := afs.WriteFile(seckeyPath, seckeySshPem, 0o600); err != nil {
		return err
	}

	fmt.Printf("Writing opk ssh public key to %s and corresponding secret key to %s\n", pubkeyPath, seckeyPath)

	certBytes = append(certBytes, []byte(" openpubkey")...)
	// Write ssh public key (certificate) to filesystem
	return afs.WriteFile(pubkeyPath, certBytes, 0o644)
}

func (l *LoginCmd) writeKeysComment(seckeyPath string, pubkeyPath string, seckeySshPem []byte, certBytes []byte, pubKeyComment string) error {
	// Write ssh secret key to filesystem
	afs := &afero.Afero{Fs: l.Fs}
	if err := afs.WriteFile(seckeyPath, seckeySshPem, 0o600); err != nil {
		return err
	}

	fmt.Printf("Writing opk ssh public key to %s and corresponding secret key to %s\n", pubkeyPath, seckeyPath)

	certBytes = append(certBytes, ' ')
	certBytes = append(certBytes, pubKeyComment...)
	// Write ssh public key (certificate) to filesystem
	return afs.WriteFile(pubkeyPath, certBytes, 0o644)
}

func (l *LoginCmd) makeSSHKeyFileName(pkt *pktoken.PKToken) string {

	regex := regexp.MustCompile(`[^a-zA-Z0-9_\-.]+`)

	issuer, err := pkt.Issuer()
	if err != nil {
		issuer = "unknown"
	}

	issuer, _ = strings.CutPrefix(issuer, "https://")

	audience, err := pkt.Audience()
	if err != nil {
		audience = "unknown"
	}

	// shorten clientID if it is too long
	if len(audience) > 20 {
		audience = audience[:20]
	}

	keyName := issuer + "-" + audience
	keyName = regex.ReplaceAllString(keyName, "_")

	return keyName
}

func (l *LoginCmd) fileExists(fPath string) bool {
	_, err := l.Fs.Open(fPath)
	return !errors.Is(err, os.ErrNotExist)
}

func IdentityString(pkt pktoken.PKToken) (string, error) {
	idt, err := oidc.NewJwt(pkt.OpToken)
	if err != nil {
		return "", err
	}
	claims := idt.GetClaims()
	if claims.Email == "" {
		return "Sub, issuer, audience: \n" + claims.Subject + " " + claims.Issuer + " " + claims.Audience, nil
	} else {
		return "Email, sub, issuer, audience: \n" + claims.Email + " " + claims.Subject + " " + claims.Issuer + " " + claims.Audience, nil
	}
}

func PrettyIdToken(pkt pktoken.PKToken) (string, error) {
	idt, err := oidc.NewJwt(pkt.OpToken)
	if err != nil {
		return "", err
	}
	idtJson, err := json.MarshalIndent(idt.GetClaims(), "", "    ")
	if err != nil {
		return "", err
	}
	return string(idtJson[:]), nil
}

func isGitHubEnvironment() bool {
	return os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" &&
		os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != ""
}

// payloadFromCompactPkt extracts the payload from a compact PK Token which
// is always the second part of the '.' separated string.
func payloadFromCompactPkt(compactPkt []byte) []byte {
	parts := bytes.Split(compactPkt, []byte("."))
	return parts[1]
}
