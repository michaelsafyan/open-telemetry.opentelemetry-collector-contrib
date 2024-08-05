// Package "foreignattr" manages the creation of foreign attributes.
// Foreign attributes are attributes referencing data in another source.
package foreignattr

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

func TestIsForeignAttrRefDoesNotFalsePositive(t *testing.T) {
	notForeignAttrs := []{
		pcommon.NewValueEmpty(),
		pcommon.NewValueStr(""),
		pcommon.NewValueStr("foo"),
		pcommon.NewValueStr("not://a/foreign/attr/even/though/looks/like/uri"),
		pcommon.NewValueBool(false),
		pcommon.NewValueBool(true),
		pcommon.NewValueInt(0),
		pcommon.NewValueInt(1),
		pcommon.NewValueInt(-1),
		pcommon.NewValueInt(5),
		pcommon.NewValueDouble(1.0),
		pcommon.NewValueMap(),
	}

	for _, v := range notForeignAttrs {
		assert.False(t, IsForeignAttrRef(v))
	}
}

func getUri(f pcommon.Value) string {
	m := f.Map()
	value, present := m.Get("uri")
	if !present {
		return ""
	}
	return value.String()
}

func hasContentType(f pcommon.Value) bool {
	m := f.Map()
	_, present := m.Get("content_type")
	return present
}

func getContentType(f pcommon.Value) string {
	m := f.Map()
	value, present := m.Get("content_type")
	if !present {
		return ""
	}
	return value.String()
}


func TestFromUri(t *testing.T) {
	f := FromUri("some://uri/string")
	assert.True(t, IsForeignAttrRef(v))
	assert.Equal(t, f.Type(), pcommon.ValueTypeMap)
	assert.Equal(t, getUri(f), "some://uri/string")
	assert.False(t, hasContentType(v))
}


func TestFromUriWithContentType(t *testing.T) {
	f := FromUriWithContentType("some://uri/string", "the/type")
	assert.True(t, IsForeignAttrRef(v))
	assert.Equal(t, f.Type(), pcommon.ValueTypeMap)
	assert.Equal(t, getUri(f), "some://uri/string")
	assert.True(t, hasContentType(v))
	assert.Equal(t, getContentType(f), "the/type")
}
