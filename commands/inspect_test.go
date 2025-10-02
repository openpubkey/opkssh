// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInspectCmdPrintf(t *testing.T) {
	buf := new(bytes.Buffer)
	inspect := NewInspectCmd("foo", buf)
	inspect.printf("Answer: %d", 42)

	output := buf.String()
	require.Contains(t, output, "Answer: 42")
}

func TestInspectCmdJson(t *testing.T) {
	inputString := `{"name":"test","options":["one","two"]}`
	input := []byte(inputString)
	outputBuf := new(bytes.Buffer)

	inspect := NewInspectCmd("foo", outputBuf)
	inspect.printJSON(input)

	output := outputBuf.String()
	require.Contains(t, output, `"name": "test",`)
	require.Contains(t, output, `"one",`)
	require.Contains(t, output, ` "two"`)
}

func TestInspectCmd(t *testing.T) {
	dummyKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINlDR6KRBqBZ1/UL96ltcZWQC7QTgru/ckbCrA/i3RfI your_email@example.com"

	f, err := os.CreateTemp("", "opkssh")
	require.NoError(t, err, "unable to create test file")

	_, err = f.WriteString(dummyKey)
	require.NoError(t, err, "unable to write test file")
	f.Close()
	defer os.Remove(f.Name())

	dummyFile := f.Name()

	tests := []struct {
		name        string
		input       string
		wantError   bool
		errorString string
	}{
		{
			name:        "Invalid input",
			input:       "scoobydoowhereareyou",
			wantError:   true,
			errorString: "failed to parse SSH key",
		},
		{
			name:      "Direct input",
			input:     dummyKey,
			wantError: false,
		},
		{
			name:      "File input",
			input:     dummyFile,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			inspect := NewInspectCmd(tt.input, buf)

			err := inspect.Run()

			if tt.wantError {
				require.Error(t, err, "Expected error but got none")
				if tt.errorString != "" {
					require.ErrorContains(t, err, tt.errorString, "Got a wrong error message")
				}
			} else {
				require.NoError(t, err, "Unexpected error")

				output := buf.String()
				require.Contains(t, output, "--- SSH Public Key Information ---")
				require.Contains(t, output, "Type: ssh-ed25519")
				require.Contains(t, output, "AAAAC3NzaC")
			}
		})
	}
}

func TestInspectFormatTime(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name         string
		input        uint64
		outputString string
	}{
		{
			name:         "epoch",
			input:        0,
			outputString: "Not set",
		},
		{
			name:         "forever",
			input:        18446744073709551615,
			outputString: "Forever",
		},
		{
			name:         "regular timestamp",
			input:        uint64(now.Unix()),
			outputString: now.Format(time.RFC3339),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := formatTime(tt.input)
			require.Equal(t, tt.outputString, output)
		})
	}
}
