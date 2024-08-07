// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "backend" provides utilities for writing to a general blob storage system.
//
// The file "factory.go" provides a means of instantiating a Registry.
package backend

import (
	"fmt"
	"strings"
)

// registryImpl is the main implementation of "Registry".
type registryImpl struct {
	// schemeToBackend contains a mapping from a URI scheme (e.g.
	// "gs", "s3", "azblob", etc.) to a corresponding backend.
	schemeToBackend map[string]BlobStorageBackend
}

// "GetBackendForUri" implements "BackendRegistry.GetBackendForUri".
func (r *registryImpl) GetBackendForURI(uri string) (BlobStorageBackend, error) {
	components := strings.SplitN(uri, "://", 2)
	if len(components) != 2 {
		return nil, fmt.Errorf("Invalid URI; missing '://' from %v", uri)
	}
	scheme := components[0]
	entry, ok := r.schemeToBackend[scheme]
	if !ok {
		return nil, fmt.Errorf("URI %v not recognized; no implementation registered for scheme %v", uri, scheme)
	}
	return entry, nil
}

// NewRegistry instantiates a new backend registry.
func NewRegistry() (Registry, error) {
	return &registryImpl{
		schemeToBackend: map[string]BlobStorageBackend{
			"azblob": &cdkBlobStorageBackend{},
			"gs":     &cdkBlobStorageBackend{},
			"s3":     &cdkBlobStorageBackend{},
		},
	}, nil
}
