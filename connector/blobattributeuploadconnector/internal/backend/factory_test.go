// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "backend" provides utilities for writing to a general blob storage system.
//
// The file "factory.go" provides a means of instantiating a Registry.
package backend

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSupportsGcsUris(t *testing.T) {
	uri := "gs://some-bucket/some-path"
	r, re := NewRegistry()
	assert.Equal(t, re, nil)
	assert.NotEqual(t, r, nil)

	b, be := r.GetBackendForURI(uri)
	assert.Equal(t, be, nil)
	assert.NotEqual(t, b, nil)
}
