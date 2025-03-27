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
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/openpubkey/openpubkey/client/choosers"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/opkssh/commands"
	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
)

var (

	// These can be overridden at build time using ldflags. For example:
	// go build -v -o /usr/local/bin/opkssh -ldflags "-X main.issuer=http://oidc.local:${ISSUER_PORT}/ -X main.clientID=web -X main.clientSecret=secret"
	Version           = "unversioned"
	issuer            = ""
	clientID          = ""
	clientSecret      = ""
	redirectURIs      = ""
	logFilePathServer = "/var/log/opkssh.log" // Remember if you change this, change it in the install script as well
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, `Error: Missing command
Try '%s --help' for more information.
`, os.Args[0])
		return 1
	}
	programStr := os.Args[0]
	commandStr := os.Args[1]

	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()

	var providerFromLdFlags providers.OpenIdProvider

	// If LDFlags issuer is set, use it to create a provider
	if issuer != "" {
		opts := providers.GetDefaultGoogleOpOptions() // TODO: Create default google like provider
		opts.Issuer = issuer
		opts.ClientID = clientID
		opts.ClientSecret = clientSecret
		opts.RedirectURIs = strings.Split(redirectURIs, ",")
		providerFromLdFlags = providers.NewGoogleOpWithOptions(opts)
	}

	switch commandStr {
	case "login":
		if len(os.Args) == 3 && (os.Args[2] == "-h" || os.Args[2] == "--help") {
			fmt.Fprintf(os.Stderr, `Usage: %s %s [OPTIONS]

Authenticate with an OpenID Connect provider to generate an SSH key for opkssh.

Login generates a key pair, then opens a browser to authenticate the user with the OpenID provider, which issues a PK token committing to the generated public key. Upon successful authentication, opkssh creates an SSH public key (~/.ssh/id_ecdsa) containing the user's PK token. By default, this SSH key expires after 24 hours, after which the user must run "opkssh login" again to generate a new key.

Users can then SSH into servers configured to use opkssh as the AuthorizedKeysCommand. The server verifies the PK token and grants access if the token is valid and the user is authorized per the auth_id policy.

Options:
	--auto-refresh           Automatically refresh PK token after login
	--log-dir=DIR            Directory to place output logs
	--provider=PROVIDER      OpenID Connect provider specification in the format:
							<issuer>,<client_id> or <issuer>,<client_id>,<client_secret>

Examples:
	opkssh login
	opkssh login --auto-refresh
	opkssh login --provider=<issuer>,<client_id>,<client_secret>
`, programStr, commandStr)

			return 0
		}

		loginCmd := flag.NewFlagSet(programStr+" "+commandStr, flag.ContinueOnError)
		autoRefresh := loginCmd.Bool("auto-refresh", false, "Used to specify whether login will begin a process that auto-refreshes PK token")
		logFilePath := loginCmd.String("log-dir", "", "Specify which directory the output log is placed")
		providerArg := loginCmd.String("provider", "", "Specify the issuer and client ID to use for OpenID Connect provider. Format is: <issuer>,<client_id> or <issuer>,<client_id>,<client_secret>")

		if err := loginCmd.Parse(os.Args[2:]); err != nil {
			// Parse writes to Stderr so we don't need to
			return 1
		}

		// If a log directory was provided, write any logs to a file in that directory AND stdout
		if *logFilePath != "" {
			logFilePath := filepath.Join(*logFilePath, "opkssh.log")
			logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0660)
			if err == nil {
				defer logFile.Close()
				multiWriter := io.MultiWriter(os.Stdout, logFile)
				log.SetOutput(multiWriter)
				log.Printf("Failed to open log for writing: %v \n", err)
			}
		} else {
			log.SetOutput(os.Stdout)
		}

		// If the user has supplied commandline arguments for the provider, use those instead of the web chooser
		var provider providers.OpenIdProvider
		if providerArg != nil && *providerArg != "" {
			parts := strings.Split(*providerArg, ",")
			if len(parts) != 2 && len(parts) != 3 {
				log.Println("Error: Invalid provider argument format. Expected format <issuer>,<client_id> or <issuer>,<client_id>,<client_secret>")
				return 1
			}
			issuerArg := parts[0]
			clientIDArg := parts[1]

			if !strings.HasPrefix(issuerArg, "https://") {
				log.Printf("Error: Invalid provider issuer value. Expected issuer to start with 'https://' got (%s) \n", issuerArg)
				return 1
			}

			if clientIDArg == "" {
				log.Printf("Error: Invalid provider client-ID value got (%s) \n", clientIDArg)
				return 1
			}

			if strings.HasPrefix(issuerArg, "https://accounts.google.com") {
				// The Google OP is strange in that it requires a client secret even if this is a public OIDC App.
				// Despite its name the Google OP client secret is a public value.
				if len(parts) != 3 {
					log.Println("Error: Invalid provider argument format. Expected format for google: <issuer>,<client_id>,<client_secret>")
					return 1
				}
				clientSecretArg := parts[2]
				if clientSecretArg == "" {
					log.Printf("Error: Invalid provider client secret value got (%s) \n", clientSecretArg)
					return 1
				}

				opts := providers.GetDefaultGoogleOpOptions()
				opts.Issuer = issuerArg
				opts.ClientID = clientIDArg
				opts.ClientSecret = clientSecretArg
				opts.GQSign = false
				provider = providers.NewGoogleOpWithOptions(opts)
			} else if strings.HasPrefix(issuerArg, "https://login.microsoftonline.com") {
				opts := providers.GetDefaultAzureOpOptions()
				opts.Issuer = issuerArg
				opts.ClientID = clientIDArg
				opts.GQSign = false
				provider = providers.NewAzureOpWithOptions(opts)
			} else if strings.HasPrefix(issuerArg, "https://gitlab.com") {
				opts := providers.GetDefaultGitlabOpOptions()
				opts.Issuer = issuerArg
				opts.ClientID = clientIDArg
				opts.GQSign = false
				provider = providers.NewGitlabOpWithOptions(opts)
			} else {
				// Generic provider - Need signing, no encryption
				opts := providers.GetDefaultGoogleOpOptions()
				opts.Issuer = issuerArg
				opts.ClientID = clientIDArg
				opts.GQSign = false

				if len(parts) == 3 {
					opts.ClientSecret = parts[2]
				}

				provider = providers.NewGoogleOpWithOptions(opts)
			}
		} else if providerFromLdFlags != nil {
			provider = providerFromLdFlags
		} else {
			googleOpOptions := providers.GetDefaultGoogleOpOptions()
			googleOpOptions.GQSign = false
			googleOp := providers.NewGoogleOpWithOptions(googleOpOptions)

			azureOpOptions := providers.GetDefaultAzureOpOptions()
			azureOpOptions.GQSign = false
			azureOp := providers.NewAzureOpWithOptions(azureOpOptions)

			gitlabOpOptions := providers.GetDefaultGitlabOpOptions()
			gitlabOpOptions.GQSign = false
			gitlabOp := providers.NewGitlabOpWithOptions(gitlabOpOptions)

			var err error
			provider, err = choosers.NewWebChooser(
				[]providers.BrowserOpenIdProvider{googleOp, azureOp, gitlabOp},
			).ChooseOp(ctx)
			if err != nil {
				log.Println("Error selecting op:", err)
				return 1
			}
		}

		// Execute login command
		if *autoRefresh {
			if providerRefreshable, ok := provider.(providers.RefreshableOpenIdProvider); ok {
				err := commands.LoginWithRefresh(ctx, providerRefreshable)
				if err != nil {
					log.Println("Error logging in:", err)
				}
			} else {
				errString := fmt.Sprintf("Error: OpenID Provider (%v) does not support auto-refresh and auto-refresh argument set to true", provider.Issuer())
				log.Println(errString)
				return 1
			}
		} else {
			err := commands.Login(ctx, provider)
			if err != nil {
				log.Println("Error logging in:", err)
				return 1
			}
		}
	case "verify":
		if len(os.Args) == 3 && (os.Args[2] == "-h" || os.Args[2] == "--help") {
			fmt.Fprintf(os.Stderr, `Usage: %s %s <PRINCIPAL (TOKEN %%u)> <CERT (TOKEN %%k)> <KEY_TYPE (TOKEN %%t)>

Verify extracts a PK token from a base64-encoded SSH certificate and verifies it against policy.
Verify expects an allowed provider file at /etc/opk/providers and a user policy file at either /etc/opk/auth_id or ~/.opk/auth_id.

This command is intended to be called by sshd as an AuthorizedKeysCommand:
	https://man.openbsd.org/sshd_config#AuthorizedKeysCommand

During installation, opkssh typically adds these lines to /etc/ssh/sshd_config:
	AuthorizedKeysCommand /usr/local/bin/opkssh verify %%u %%k %%t
	AuthorizedKeysCommandUser opksshuser

Argument descriptions:
	%%u   Target username (requested principal)
	%%k   Base64-encoded SSH public key (SSH certificate) provided for authentication
	%%t   Public key type (SSH certificate format, e.g., ecdsa-sha2-nistp256-cert-v01@openssh.com)

Verification checks performed:
	1. Ensures the PK token is properly formed, signed, and issued by the specified OpenID Provider (OP).
	2. Confirms the PK token's issue (iss) and client ID (audience) are listed in the allowed provider file (/etc/opk/providers) and the token is not expired.
	3. Validates the identity (email or sub) in the PK token against user policies (/etc/opk/auth_id or ~/.opk/auth_id) to ensure it can assume the requested username (principal).

If all checks pass, Verify authorizes the SSH connection.

Example usage:
	opkssh verify root <base64-encoded-cert> ecdsa-sha2-nistp256-cert-v01@openssh.com
`, programStr, commandStr)

			return 0
		}

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

		if len(os.Args) != 5 {
			log.Println("Invalid number of arguments for verify, expected: `<User (TOKEN u)> <Cert (TOKEN k)> <Key type (TOKEN t)>`")
			return 1
		}
		userArg := os.Args[2]
		certB64Arg := os.Args[3]
		typArg := os.Args[4]

		providerPolicyPath := "/etc/opk/providers"
		providerPolicy, err := policy.NewProviderFileLoader().LoadProviderPolicy(providerPolicyPath)

		if err != nil {
			log.Println("Failed to open /etc/opk/providers:", err)
			return 1
		}
		printConfigProblems()
		log.Println("Providers loaded: ", providerPolicy.ToString())

		pktVerifier, err := providerPolicy.CreateVerifier()
		if err != nil {
			log.Println("Failed to create pk token verifier (likely bad configuration):", err)
			return 1
		}

		// Execute verify command
		v := commands.VerifyCmd{
			PktVerifier: *pktVerifier,
			CheckPolicy: commands.OpkPolicyEnforcerFunc(userArg),
		}
		if authKey, err := v.AuthorizedKeysCommand(ctx, userArg, typArg, certB64Arg); err != nil {
			log.Println("failed to verify:", err)
			return 1
		} else {
			log.Println("successfully verified")
			// sshd is awaiting a specific line, which we print here. Printing anything else before or after will break our solution
			fmt.Println(authKey)
			return 0
		}
	case "add":
		if len(os.Args) == 3 && (os.Args[2] == "-h" || os.Args[2] == "--help") {
			fmt.Fprintf(os.Stderr, `Usage: %s %s <PRINCIPAL> <EMAIL|SUB> <ISSUER>

Add creates a new policy entry in the auth_id policy file, granting SSH access to the specified email or subscriber ID (sub).

Add first attempts to write the policy to the system-wide file at /etc/opk/auth_id.  
If lacks permissions to updated this file, it falls back to the user-specific file at ~/.opk/auth_id.

Arguments:
  PRINCIPAL      The target user account (requested principal).
  EMAIL|SUB      Email address or subscriber ID authorized to assume this principal.
  ISSUER         OpenID Connect provider (issuer) URL associated with the email/sub.

Example usage:
  opkssh add root alice@example.com https://accounts.google.com
  opkssh add alice 103030642802723203118 https://accounts.google.com
`, programStr, commandStr)
			return 0
		}

		if len(os.Args) != 5 {
			fmt.Fprintf(os.Stderr, "Invalid number of arguments for add, expected: `<Principal> <Email> <Issuer>`\n")
			return 1
		}
		inputPrincipal := os.Args[2]
		inputEmail := os.Args[3]
		inputIssuer := os.Args[4]

		// Convenience aliases to save user time (who is going to remember the hideous Azure issuer string)
		switch inputIssuer {
		case "google":
			inputIssuer = "https://accounts.google.com"
		case "azure", "microsoft":
			inputIssuer = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
		case "gitlab":
			inputIssuer = "https://gitlab.com"
		}

		// Execute add command
		a := commands.AddCmd{
			HomePolicyLoader:   policy.NewHomePolicyLoader(),
			SystemPolicyLoader: policy.NewSystemPolicyLoader(),
			Username:           inputPrincipal,
		}
		if policyFilePath, err := a.Add(inputPrincipal, inputEmail, inputIssuer); err != nil {
			fmt.Fprintf(os.Stderr, "failed to add to policy: %v\n", err)
			return 1
		} else {
			fmt.Fprintf(os.Stdout, "Successfully added new policy to %s\n", policyFilePath)
			return 0
		}
	case "--help", "help":
		fmt.Fprintf(os.Stderr, `Usage: %s <command> [OPTIONS]

SSH with OpenPubkey CLI.

This program allows users to login and create SSH key pairs using their OpenID Connect identity, add policies to auth_id policy files, and verify OpenPubkey SSH certificates for use with sshd's AuthorizedKeysCommand.

Commands:
	add PRINCIPAL EMAIL ISSUER       Add a new rule to the policy file
	login                            Authenticate with an OpenID Connect provider to generate an SSH key
	verify PRINCIPAL CERT KEY_TYPE   Verify an SSH key (used by sshd AuthorizedKeysCommand)

Options:
	-h, --help                       Show this help message
	-v, --version                    Show version information

Examples:
	opkssh login
	opkssh add root alice@example.com https://accounts.google.com

opkssh online help: <https://github.com/openpubkey/opkssh/blob/main/README.md>
`, programStr)
		return 0
	case "--version", "-v":
		fmt.Fprintf(os.Stderr, `opkssh version %s`, Version)
		return 0
	case "readhome":
		// This command called as part of AuthorizedKeysCommand. It is used to
		// read the user's home policy file (`~/.opk/auth_id`) with sudoer permissions.
		// This allows us to use an unprivileged user as the AuthorizedKeysCommand user.
		if len(os.Args) != 3 {
			fmt.Fprintf(os.Stderr, "Invalid number of arguments for %s %s, expected: opkssh readhome <username>\n", programStr, commandStr)
			return 1
		}
		userArg := os.Args[2]
		if fileBytes, err := commands.ReadHome(userArg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read user's home policy file: %v\n", err)
			return 1
		} else {
			fmt.Fprint(os.Stdout, string(fileBytes))
			return 0
		}
	default:
		fmt.Fprintf(os.Stderr, `%s: invalid option -- '%s'
Try '%s --help' for more information.
`, os.Args[0], commandStr, os.Args[0])
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
