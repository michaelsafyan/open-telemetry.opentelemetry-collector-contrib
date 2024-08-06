// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "contenttype" provides utilities for guessing/inferring content types.
package contenttype

import "net/http"

// DeduceContentType attempts to deduce the content type of the given information.
//
// Args:
//   uri: The destination URI to which to write the data.
//   data: The actual data that will be written for which to infer the type.
//
// Returns:
//  (MIME type, error): the inferred content type or an error
func DeduceContentType(uri string, data []byte) (string, error) {
	// This additional wrapping layer around "net/http" exists to
	// allow for future evolution of the content detection (such
	// as to use alternative dependencies or to add detection that
	// is more fine-grained for certain observability use cases).
	contentType := http.DetectContentType(data)
	return contentType, nil
}
