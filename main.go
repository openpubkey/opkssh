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

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/openpubkey/opkssh/commands"
	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/cobra"
)

var (
	// These can be overridden at build time using ldflags. For example:
	// go build -v -o /usr/local/bin/opkssh -ldflags "-X main.Version=version"
	Version           = "unversioned"
	logFilePathServer = "/var/log/opkssh.log" // Remember if you change this, change it in the install script as well
)

func main() {
	os.Exit(run())
}

func run() int {
	rootCmd := &cobra.Command{
		SilenceUsage: true,
		Use:          "opkssh",
		Short:        "SSH with OpenPubkey",
		Version:      Version,
		Long: `SSH with OpenPubkey

This program allows users to:
  - Login and create SSH key pairs using their OpenID Connect identity
  - Add policies to auth_id policy files
  - Verify OpenPubkey SSH certificates for use with sshd's AuthorizedKeysCommand`,
		Example: `  opkssh login
  opkssh add root alice@example.com https://accounts.google.com`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	addCmd := &cobra.Command{
		SilenceUsage: true,
		Use:          "add <PRINCIPAL> <EMAIL|SUB|GROUP> <ISSUER>",
		Short:        "Appends new rule to the policy file",
		Long: `Add appends a new policy entry in the auth_id policy file granting SSH access to the specified email or subscriber ID (sub) or group.

It first attempts to write to the system-wide file (/etc/opk/auth_id). If it lacks permissions to update this file it falls back to writing to the user-specific file (~/.opk/auth_id).

Arguments:
  PRINCIPAL            The target user account (requested principal).
  EMAIL|SUB|GROUP      Email address, subscriber ID or group authorized to assume this principal. If using an OIDC group, the argument needs to be in the format of oidc:groups:<groupId>.
  ISSUER               OpenID Connect provider (issuer) URL associated with the email/sub/group.
`,
		Args: cobra.ExactArgs(3),
		Example: `  opkssh add root alice@example.com https://accounts.google.com
  opkssh add alice 103030642802723203118 https://accounts.google.com
  opkssh add developer oidc:groups:developer https://accounts.google.com`,
		RunE: func(cmd *cobra.Command, args []string) error {
			inputPrincipal := args[0]
			inputEmail := args[1]
			inputIssuer := args[2]

			// Convenience aliases to save user time (who is going to remember the hideous Azure issuer string)
			switch inputIssuer {
			case "google":
				inputIssuer = "https://accounts.google.com"
			case "azure", "microsoft":
				inputIssuer = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
			case "gitlab":
				inputIssuer = "https://gitlab.com"
			case "hello":
				inputIssuer = "https://issuer.hello.coop"
			}

			add := commands.AddCmd{
				HomePolicyLoader:   policy.NewHomePolicyLoader(),
				SystemPolicyLoader: policy.NewSystemPolicyLoader(),
				Username:           inputPrincipal,
			}
			policyFilePath, err := add.Run(inputPrincipal, inputEmail, inputIssuer)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to add to policy: %v\n", err)
				return err
			}
			fmt.Fprintf(os.Stdout, "Successfully added new policy to %s\n", policyFilePath)
			return nil
		},
	}
	rootCmd.AddCommand(addCmd)

	var autoRefreshArg bool
	var configPathArg string
	var createConfigArg bool
	var configureArg bool
	var logDirArg string
	var providerArg string
	var sendAccessTokenArg bool
	var disableBrowserOpenArg bool
	var printIdTokenArg bool
	var keyPathArg string
	loginCmd := &cobra.Command{
		SilenceUsage: true,
		Use:          "login [alias]",
		Short:        "Authenticate with an OpenID Provider to generate an SSH key for opkssh",
		Long: `Login creates opkssh SSH keys

Login generates a key pair, then opens a browser to authenticate the user with the OpenID Provider. Upon successful authentication, opkssh creates an SSH public key (~/.ssh/id_ecdsa) containing the user's PK token. By default, this SSH key expires after 24 hours, after which the user must run "opkssh login" again to generate a new key.

Users can then SSH into servers configured to use opkssh as the AuthorizedKeysCommand. The server verifies the PK token and grants access if the token is valid and the user is authorized per the auth_id policy.
Arguments:
  alias      The provider alias to use. If not specified, the OPKSSH_DEFAULT provider will be used. The aliases are defined by the OPKSSH_PROVIDERS environment variable. The format is <alias>,<issuer>,<client_id>,<client_secret>,<scopes>
`,
		Example: `  opkssh login
  opkssh login google
  opkssh login --provider=<issuer>,<client_id>,<client_secret>,<scopes>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigs
				cancel()
			}()

			var providerAliasArg string
			if len(args) > 0 {
				providerAliasArg = args[0]
			}

			login := commands.NewLogin(autoRefreshArg, configPathArg, createConfigArg, configureArg, logDirArg, sendAccessTokenArg, disableBrowserOpenArg, printIdTokenArg, providerArg, keyPathArg, providerAliasArg)
			if err := login.Run(ctx); err != nil {
				log.Println("Error executing login command:", err)
				return err
			}
			return nil
		},
		Args: cobra.MaximumNArgs(1),
	}

	// Define flags for login.
	loginCmd.Flags().BoolVar(&autoRefreshArg, "auto-refresh", false, "Automatically refresh PK token after login")
	loginCmd.Flags().StringVar(&configPathArg, "config-path", "", "Path to the client config file. Default: ~/.opk/config.yml on linux and %APPDATA%\\.opk\\config.yml on windows")
	loginCmd.Flags().BoolVar(&createConfigArg, "create-config", false, "Creates a client config file if it does not exist")
	loginCmd.Flags().BoolVar(&configureArg, "configure", false, "Apply changes to ssh config and create ~/.ssh/opkssh directory")
	loginCmd.Flags().StringVar(&logDirArg, "log-dir", "", "Directory to write output logs")
	loginCmd.Flags().BoolVar(&disableBrowserOpenArg, "disable-browser-open", false, "Set this flag to disable opening the browser. Useful for choosing the browser you want to use")
	loginCmd.Flags().BoolVar(&printIdTokenArg, "print-id-token", false, "Set this flag to print out the contents of the id_token. Useful for inspecting claims")
	loginCmd.Flags().BoolVar(&sendAccessTokenArg, "send-access-token", false, "Set this flag to send the Access Token as well as the PK Token in the SSH cert. The Access Token is used to call the userinfo endpoint to get claims not included in the ID Token")
	loginCmd.Flags().StringVar(&providerArg, "provider", "", "OpenID Provider specification in the format: <issuer>,<client_id> or <issuer>,<client_id>,<client_secret> or <issuer>,<client_id>,<client_secret>,<scopes>")
	loginCmd.Flags().StringVarP(&keyPathArg, "private-key-file", "i", "", "Path where private keys is written")
	rootCmd.AddCommand(loginCmd)

	readhomeCmd := &cobra.Command{
		SilenceUsage: true,
		Use:          "readhome <PRINCIPAL>",
		Short:        "Read the principal's home policy file",
		Long: `Read the principal's policy file (/home/<PRINCIPAL>/.opk/auth_id).

You should not call this command directly. It is called by the opkssh verify command as part of the AuthorizedKeysCommand process to read the user's policy  (principals) home file (~/.opk/auth_id) with sudoer permissions. This allows us to use an unprivileged user as the AuthorizedKeysCommand user.
`,
		Args:    cobra.ExactArgs(1),
		Example: `  opkssh readhome alice`,
		RunE: func(cmd *cobra.Command, args []string) error {
			userArg := os.Args[2]
			if fileBytes, err := commands.ReadHome(userArg); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to read user's home policy file: %v\n", err)
				return err
			} else {
				fmt.Fprint(os.Stdout, string(fileBytes))
				return nil
			}
		},
	}
	rootCmd.AddCommand(readhomeCmd)

	var serverConfigPathArg string
	verifyCmd := &cobra.Command{
		SilenceUsage: true,
		Use:          "verify <PRINCIPAL> <CERT> <KEY_TYPE>",
		Short:        "Verify an SSH key (used by sshd AuthorizedKeysCommand)",
		Long: `Verify extracts a PK token from a base64-encoded SSH certificate and verifies it against policy. It expects an allowed provider file at /etc/opk/providers and a user policy file at either /etc/opk/auth_id or ~/.opk/auth_id.

This command is intended to be called by sshd as an AuthorizedKeysCommand:
  https://man.openbsd.org/sshd_config#AuthorizedKeysCommand

During installation, opkssh typically adds these lines to /etc/ssh/sshd_config:
  AuthorizedKeysCommand /usr/local/bin/opkssh verify %%u %%k %%t
  AuthorizedKeysCommandUser opksshuser

Where the tokens in /etc/ssh/sshd_config are defined as:
  %%u   Target username (requested principal)
  %%k   Base64-encoded SSH public key (SSH certificate) provided for authentication
  %%t   Public key type (SSH certificate format, e.g., ecdsa-sha2-nistp256-cert-v01@openssh.com)

Verification checks performed:
  1. Ensures the PK token is properly formed, signed, and issued by the specified OpenID Provider (OP).
  2. Confirms the PK token's issue (iss) and client ID (audience) are listed in the allowed provider file (/etc/opk/providers) and the token is not expired.
  3. Validates the identity (email or sub) in the PK token against user policies (/etc/opk/auth_id or ~/.opk/auth_id) to ensure it can assume the requested username (principal).

If all checks pass, Verify authorizes the SSH connection.

Arguments:
  PRINCIPAL    Target username.
  CERT         Base64-encoded SSH certificate.
  KEY_TYPE     SSH certificate key type (e.g., ecdsa-sha2-nistp256-cert-v01@openssh.com)`,
		Args:    cobra.ExactArgs(3),
		Example: `  opkssh verify root <base64-encoded-cert> ecdsa-sha2-nistp256-cert-v01@openssh.com`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			// Setup logger
			logFile, err := os.OpenFile(logFilePathServer, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0660) // Owner and group can read/write
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening log file: %v\n", err)
				// It could be very difficult to figure out what is going on if the log file was deleted. Hopefully this message saves someone an hour of debugging.
				fmt.Fprintf(os.Stderr, "Check if log exists at %v, if it does not create it with permissions: chown root:opksshuser %v; chmod 660 %v\n", logFilePathServer, logFilePathServer, logFilePathServer)
			} else {
				defer logFile.Close()
				log.SetOutput(logFile)
			}

			// Logs if using an unsupported OpenSSH version
			checkOpenSSHVersion()

			// The "AuthorizedKeysCommand" func is designed to be used by sshd and specified as an AuthorizedKeysCommand
			// ref: https://man.openbsd.org/sshd_config#AuthorizedKeysCommand
			log.Println(strings.Join(os.Args, " "))

			userArg := args[0]
			certB64Arg := args[1]
			typArg := args[2]

			providerPolicyPath := "/etc/opk/providers"
			providerPolicy, err := policy.NewProviderFileLoader().LoadProviderPolicy(providerPolicyPath)
			if err != nil {
				log.Println("Failed to open /etc/opk/providers:", err)
				return err
			}

			printConfigProblems()
			log.Println("Providers loaded: ", providerPolicy.ToString())

			pktVerifier, err := providerPolicy.CreateVerifier()
			if err != nil {
				log.Println("Failed to create pk token verifier (likely bad configuration):", err)
				return err
			}

			v := commands.NewVerifyCmd(*pktVerifier, commands.OpkPolicyEnforcerFunc(userArg), serverConfigPathArg)
			if err := v.SetEnvVarInConfig(); err != nil {
				log.Println("Failed to set environment variables in config:", err)
			}

			if authKey, err := v.AuthorizedKeysCommand(ctx, userArg, typArg, certB64Arg); err != nil {
				log.Println("failed to verify:", err)
				return err
			} else {
				log.Println("successfully verified")
				// sshd is awaiting a specific line, which we print here. Printing anything else before or after will break our solution
				fmt.Println(authKey)
				return nil
			}
		},
	}
	verifyCmd.Flags().StringVar(&serverConfigPathArg, "config-path", "/etc/opk/config.yml", "Path to the server config file. Default: /etc/opk/config.yml.")
	rootCmd.AddCommand(verifyCmd)

	err := rootCmd.Execute()
	if err != nil {
		return 1
	}
	return 0
}

func printConfigProblems() {
	problems := files.ConfigProblems().GetProblems()
	if len(problems) > 0 {
		log.Println("Warning: Encountered the following configuration problems:")
		for _, problem := range problems {
			log.Println(problem.String())
		}
	}
}

// OpenSSH used to impose a 4096-octet limit on the string buffers available to
// the percent_expand function. In October 2019 as part of the 8.1 release,
// that limit was removed. If you exceeded this amount it would fail with
// fatal: percent_expand: string too long
// The following two functions check whether the OpenSSH version on the
// system running the verifier is greater than or equal to 8.1;
// if not then prints a warning
func checkOpenSSHVersion() {
	// Redhat/centos does not recognize `sshd -V` but does recognize `ssh -V`
	// Ubuntu recognizes both
	cmd := exec.Command("ssh", "-V")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Println("Warning: Error executing ssh -V:", err)
		return
	}

	if ok, _ := isOpenSSHVersion8Dot1OrGreater(string(output)); !ok {
		log.Println("Warning: OpenPubkey SSH requires OpenSSH v. 8.1 or greater")
	}
}

func isOpenSSHVersion8Dot1OrGreater(opensshVersion string) (bool, error) {
	// To handle versions like 9.9p1; we only need the initial numeric part for the comparison
	re, err := regexp.Compile(`^(\d+(?:\.\d+)*).*`)
	if err != nil {
		fmt.Println("Error compiling regex:", err)
		return false, err
	}

	opensshVersion = strings.TrimPrefix(
		strings.Split(opensshVersion, ", ")[0],
		"OpenSSH_",
	)

	matches := re.FindStringSubmatch(opensshVersion)

	if len(matches) <= 0 {
		fmt.Println("Invalid OpenSSH version")
		return false, errors.New("invalid OpenSSH version")
	}

	version := matches[1]

	if version >= "8.1" {
		return true, nil
	}

	return false, nil
}
