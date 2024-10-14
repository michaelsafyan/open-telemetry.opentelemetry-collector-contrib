// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "foreignattr" manages the creation of foreign attributes.
// Foreign attributes are attributes referencing data in another source.
package foreignattr

import (
	"fmt"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

// Implements interface "ForeignAttrRef"
type foreignAttrRefImpl struct {
	// The URI to the data uploaded to some remote storage.
	uri string

	// The content type of the uploaded data.
	contentType string
}

// Constructs a reference with URI and content type.
func FromURIWithContentType(uri string, contentType string) ForeignAttrRef {
	return &foreignAttrRefImpl{
		uri:         uri,
		contentType: contentType,
	}
}

// Convenience function for omitting the content type.
func FromURI(uri string) ForeignAttrRef {
	return FromURIWithContentType(uri, "")
}

// Sets the foreign attribute reference in the map.
func (far *foreignAttrRefImpl) SetInMap(key string, m pcommon.Map) {
	ukey := fmt.Sprintf("%s.ref.uri", key)
	ckey := fmt.Sprintf("%s.ref.content_type", key)
	m.Remove(ukey)
	m.Remove(ckey)
	m.PutStr(ukey, far.uri)
	if len(far.contentType) > 0 {
		m.PutStr(ckey, far.contentType)
	}
}
