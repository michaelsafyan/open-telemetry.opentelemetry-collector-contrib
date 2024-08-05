// Package "blobattributeuploadconnector" provides a connector that writes
// certain specified attributes to a blob storage backend.
//
// The file "config_test.go" validates the "config.go" file.
package blobattributeuploadconnector

import (
	"go.opentelemetry.io/collector/confmap/confmaptest"
	"testing"
	"path/filepath"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	_, err := confmaptest.LoadConf(filepath.Join("testdata", "config.yaml"))
	require.NoError(t, err)
}
