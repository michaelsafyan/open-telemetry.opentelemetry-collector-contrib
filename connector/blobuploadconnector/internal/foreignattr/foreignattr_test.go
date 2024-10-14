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

func TestSetInMapUriOnly(t *testing.T) {
	f := FromURI("some://uri/string")
	m := pcommon.NewMap()
	f.SetInMap("somekey", m)

	uriValue, uriPresent := m.Get("somekey.ref.uri")
	_, contentTypePresent := m.Get("somekey.ref.content_type")

	assert.True(t, uriPresent)
	assert.False(t, contentTypePresent)

	assert.Equal(t, uriValue.Type(), pcommon.ValueTypeStr)
	assert.Equal(t, uriValue.Str(), "some://uri/string")
}

func TestSetInMapUriAndContentType(t *testing.T) {
	f := FromURIWithContentType("some://uri/string", "the/type")

	m := pcommon.NewMap()
	f.SetInMap("somekey", m)

	uriValue, uriPresent := m.Get("somekey.ref.uri")
	contentTypeValue, contentTypePresent := m.Get("somekey.ref.content_type")

	assert.True(t, uriPresent)
	assert.True(t, contentTypePresent)

	assert.Equal(t, uriValue.Type(), pcommon.ValueTypeStr)
	assert.Equal(t, uriValue.Str(), "some://uri/string")

	assert.Equal(t, contentTypeValue.Type(), pcommon.ValueTypeStr)
	assert.Equal(t, contentTypeValue.Str(), "the/type")
}

func TestSetInMapReplacesExistingRefValues(t *testing.T) {
	oldValue := FromURIWithContentType("old://uri", "old/type")
	m := pcommon.NewMap()
	oldValue.SetInMap("somekey", m)

	f := FromURI("some://uri/string")
	f.SetInMap("somekey", m)

	uriValue, uriPresent := m.Get("somekey.ref.uri")
	_, contentTypePresent := m.Get("somekey.ref.content_type")

	assert.True(t, uriPresent)
	assert.False(t, contentTypePresent)

	assert.Equal(t, uriValue.Type(), pcommon.ValueTypeStr)
	assert.Equal(t, uriValue.Str(), "some://uri/string")
}

func TestSetInMapDoesNotRemoveOriginalValue(t *testing.T) {
	m := pcommon.NewMap()
	m.PutStr("somekey", "the original value")

	f := FromURI("some://uri/string")
	f.SetInMap("somekey", m)

	originalValue, originalPresent := m.Get("somekey")
	uriValue, uriPresent := m.Get("somekey.ref.uri")

	assert.True(t, originalPresent)
	assert.True(t, uriPresent)

	assert.Equal(t, originalValue.Type(), pcommon.ValueTypeStr)
	assert.Equal(t, originalValue.Str(), "the original value")

	assert.Equal(t, uriValue.Type(), pcommon.ValueTypeStr)
	assert.Equal(t, uriValue.Str(), "some://uri/string")
}
