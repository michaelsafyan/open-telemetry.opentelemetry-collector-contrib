// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "foreignattr" manages the creation of foreign attributes.
// Foreign attributes are attributes referencing data in another source.
package foreignattr

import "go.opentelemetry.io/collector/pdata/pcommon"

// Represents a reference to an attribute uploaded to external storage.
type ForeignAttrRef interface {
	// Sets a reference to the given attribute in the map.
	//
	// Writes to keys "${key}.ref.*", with "${key}.ref.uri" as
	// mandatory; other ".ref.*" keys may be given other metadata
	// such as "${key}.ref.content_type" with the MIME type.
	SetInMap(key string, m pcommon.Map)
}
