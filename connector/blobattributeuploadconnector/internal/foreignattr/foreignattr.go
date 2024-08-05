// Package "foreignattr" manages the creation of foreign attributes.
// Foreign attributes are attributes referencing data in another source.
package foreignattr

import "go.opentelemetry.io/collector/pdata/pcommon"

const typeKey = "type"
const typeKeyVal = "ForeignAttrRef"
const uriKey = "uri"
const contentTypeKey = "content_type"


// IsForeignAttrRef tests whether a given value represents a
// foreign attribute reference.
func IsForeignAttrRef(v pcommon.Value) bool {
	if v.Type() != pcommon.ValueTypeMap {
		return false
	}

	m := v.Map()
	typeValue, typePresent := m.Get(typeKey)
	if !typePresent {
		return false
	}

	if typeValue.Type() != pcommon.ValueTypeStr {
		return false
	}

	if typeValue.String() != typeKeyVal {
		return false
	}

	uriValue, uriPresent := m.Get(uriKey)
	if !uriPresent {
		return false
	}

	if uriValue.Type() != pcommon.ValueTypeStr {
		return false
	}

	return true
}

// FromUri creates a foreign attribute reference from the given URI.
func FromUri(uri string) pcommon.Value {
	v := pcommon.NewValueMap()
	m := v.Map()
	m.PutStr(typeKey, typeKeyVal)
	m.PutStr(uriKey, uri)
	return v
}

// FromUriWithContentType creates a foreign attribute reference that includes
// both a URI as well as a content type associated with it.
func FromUriWithContentType(uri string, contentType string) pcommon.Value {
	v := FromUri(uri)
	v.Map().PutStr(contentTypeKey, contentType)
	return v
}
