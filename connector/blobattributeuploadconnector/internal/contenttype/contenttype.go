// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "contenttype" provides utilities for guessing/inferring content types.
package contenttype

import (
	"encoding/json"
	"net/http"
	"strings"
)

// DeduceContentType attempts to deduce the content type of the given information.
//
// Args:
//   uri: The destination URI to which to write the data.
//   data: The actual data that will be written for which to infer the type.
//
// Returns:
//  (MIME type, error): the inferred content type or an error
func DeduceContentType(uri string, data []byte) (string, error) {
	detectedContentType := strings.TrimSpace(strings.TrimRight(http.DetectContentType(data), ";"))

	if detectedContentType == "text/plain" {
		trimmedContent := strings.TrimSpace(string(data))
		if strings.HasPrefix(trimmedContent, "{") && strings.HasSuffix(trimmedContent, "}") && json.Valid(data) {
			if strings.HasSuffix(uri, ".yaml") {
				return "application/yaml", nil
			}
			return "application/json", nil
		}
	}

	return detectedContentType, nil
}
