// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "foreignattr" manages the creation of foreign attributes.
// Foreign attributes are attributes referencing data in another source.
package foreignattr

import (
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"testing"
)

func TestIsForeignAttrRefDoesNotFalsePositive(t *testing.T) {
	notForeignAttrs := []pcommon.Value{
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
	if value.Type() != pcommon.ValueTypeStr {
		return ""
	}
	return value.Str()
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
	if value.Type() != pcommon.ValueTypeStr {
		return ""
	}
	return value.Str()
}

func TestFromUri(t *testing.T) {
	f := FromUri("some://uri/string")
	assert.True(t, IsForeignAttrRef(f))
	assert.Equal(t, f.Type(), pcommon.ValueTypeMap)
	assert.Equal(t, getUri(f), "some://uri/string")
	assert.False(t, hasContentType(f))
}

func TestFromUriWithContentType(t *testing.T) {
	f := FromUriWithContentType("some://uri/string", "the/type")
	assert.True(t, IsForeignAttrRef(f))
	assert.Equal(t, f.Type(), pcommon.ValueTypeMap)
	assert.Equal(t, getUri(f), "some://uri/string")
	assert.True(t, hasContentType(f))
	assert.Equal(t, getContentType(f), "the/type")
}
