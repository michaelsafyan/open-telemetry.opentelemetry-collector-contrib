// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "backend" provides utilities for writing to a general blob storage system.
//
// The file "interfaces.go" defines the relevant interfaces of this subpackage.
package backend

import (
	"context"
)

// UploadMetadata provides read-only access to information related to the content being uploaded.
type UploadMetadata interface {
	// ContentType returns the content-type of the information that is being uploaded.
	ContentType() string

	// Additional metadata to use when storing the data. This metadata should typically
	// be used for provenance information such as, for example, storing the trace ID
	// and span ID of the span from which this data originated.
	Labels() map[string]string
}

// BlobStorageBackend represents a general interface for writing to a blob store.
type BlobStorageBackend interface {
	// Upload writes to the given destination URI.
	Upload(ctx context.Context, uri string, data []byte, metadata UploadMetadata) error
}

// Registry maps URIs (typically based on prefix) to an associated backend.
type Registry interface {
	// GetBackendForURI returns the backend for the specified URI if available.
	GetBackendForURI(uri string) (BlobStorageBackend, error)
}
