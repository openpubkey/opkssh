package config

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetKeyDir(t *testing.T) {

	const (
		absoluteKeyDir = "/opt/opk"
	)

	relativeConfig := KeyManagementConfig{
		DefaultKeyDir: ".opk",
	}
	absoluteConfig := KeyManagementConfig{
		DefaultKeyDir: absoluteKeyDir,
	}

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name         string
		config       *KeyManagementConfig
		exprectedDir string
	}{
		{
			name:         "Testing relative config directory",
			config:       &relativeConfig,
			exprectedDir: path.Join(homeDir, ".opk"),
		},
		{
			name:         "testing absolute config directory",
			config:       &absoluteConfig,
			exprectedDir: absoluteKeyDir,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			var (
				dir string
			)

			dir, err = tt.config.GetKeyDir()
			require.NoError(t, err)

			require.Equal(t, tt.exprectedDir, dir)
		})
	}
}
