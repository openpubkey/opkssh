package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetKeyDir(t *testing.T) {

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	absPath := filepath.Join(homeDir, ".opk")

	relativeConfig := KeyManagementConfig{
		DefaultKeyDir: ".opk",
	}
	absoluteConfig := KeyManagementConfig{
		DefaultKeyDir: absPath,
	}

	tests := []struct {
		name         string
		config       *KeyManagementConfig
		exprectedDir string
	}{
		{
			name:         "Testing relative config directory",
			config:       &relativeConfig,
			exprectedDir: absPath,
		},
		{
			name:         "testing absolute config directory",
			config:       &absoluteConfig,
			exprectedDir: absPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			dir, err := tt.config.GetKeyDir()
			require.NoError(t, err)

			require.Equal(t, tt.exprectedDir, dir)
		})
	}
}
