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
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
	"golang.org/x/crypto/ssh"
)

// LogoutCmd represents the logout command that clears all local certificates.
type LogoutCmd struct {
	// Inputs
	Fs         afero.Fs
	LogDirArg  string // Directory to write output logs
	KeyPathArg string // Path where SSH private key is written
	KeyTypeArg KeyType
	Verbosity  int // Default verbosity is 0, 1 is verbose, 2 is debug
}

// NewLogout creates a new LogoutCmd instance with the provided arguments.
func NewLogout(
	logDirArg string,
	keyPathArg string,
) *LogoutCmd {
	return &LogoutCmd{
		Fs:         afero.NewOsFs(),
		LogDirArg:  logDirArg,
		KeyPathArg: keyPathArg,
	}
}

func (l *LogoutCmd) Run(_ context.Context) error {
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

	return l.logout()
}

func (l *LogoutCmd) logout() error {
	userhomeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user config dir: %v", err)
	}

	const opkSshDir = ".ssh/opkssh"
	var userOpkSshDir = filepath.Join(userhomeDir, opkSshDir)

	userOpkSshDirExists := l.fileExists(userOpkSshDir)

	// remove ssh secret key and public key to filesystem
	if l.KeyPathArg != "" {
		l.removeManagedKeys(l.KeyPathArg, l.KeyPathArg+"-cert.pub")
	} else if userOpkSshDirExists {
		l.removeKeysFromOpkSSHDir(userOpkSshDir)
	} else {
		return l.removeKeysFromSSHDir()
	}

	return nil
}

func (l *LogoutCmd) removeKeysFromOpkSSHDir(userOpkSshDir string) {
	files, err := os.ReadDir(userOpkSshDir)
	if err != nil {
		return
	}

	var userOpkSshConfig = filepath.Join(userOpkSshDir, "config")

	afs := &afero.Afero{Fs: l.Fs}

	// empty config file
	err = afs.WriteFile(userOpkSshConfig, []byte{}, 0o600)
	if err != nil {
		log.Printf("Failed to write empty config file %s: %s\n", userOpkSshConfig, err)
	} else {
		log.Printf("Cleared config file %s", userOpkSshConfig)
	}

	// delete all identity files
	for _, file := range files {
		if file.IsDir() || strings.HasPrefix(file.Name(), ".") {
			continue
		}

		// we want the config file to be present, so skip it
		// the .ssh/config can still include it
		if file.Name() == "config" {
			continue
		}

		identityFile := filepath.Join(userOpkSshDir, file.Name())

		if err := l.Fs.Remove(identityFile); err != nil {
			log.Printf("Failed removing identity file at %s: %s\n", identityFile, err)
		} else {
			log.Printf("Removing identity file at %s\n", identityFile)
		}
	}
}

func (l *LogoutCmd) removeKeysFromSSHDir() error {
	homePath, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	sshPath := filepath.Join(homePath, ".ssh")

	for _, keyFilename := range []string{"id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk"} {
		seckeyPath := filepath.Join(sshPath, keyFilename)
		pubkeyPath := seckeyPath + "-cert.pub"

		l.removeManagedKeys(seckeyPath, pubkeyPath)
	}

	return nil
}

func (l *LogoutCmd) removeManagedKeys(seckeyPath, pubkeyPath string) {
	afs := &afero.Afero{Fs: l.Fs}

	// skip files that don't exist
	if !l.fileExists(pubkeyPath) {
		return
	}

	sshPubkey, err := afs.ReadFile(pubkeyPath)
	if err != nil {
		log.Println("Failed to read:", pubkeyPath)

		return
	}

	_, comment, _, _, err := ssh.ParseAuthorizedKey(sshPubkey)
	if err != nil {
		log.Println("Failed to parse:", pubkeyPath)

		return
	}

	// If the key comment is "openpubkey" then we generated it
	if comment == "openpubkey" {
		if ok, _ := afs.Exists(seckeyPath); ok {
			if err := afs.Remove(seckeyPath); err != nil {
				log.Printf("Failed to remove %s: %s\n", seckeyPath, err)
			} else {
				log.Println("Removing key from filesystem" + seckeyPath)
			}
		}

		if err := afs.Remove(pubkeyPath); err != nil {
			log.Printf("Failed to remove %s: %s\n", pubkeyPath, err)
		} else {
			log.Println("Removing certificate from filesystem" + pubkeyPath)
		}
	} else {
		log.Printf("Key %s was not generated by openpubkey, skipping\n", seckeyPath)
	}
}

func (l *LogoutCmd) fileExists(fPath string) bool {
	_, err := l.Fs.Open(fPath)
	return !errors.Is(err, os.ErrNotExist)
}
