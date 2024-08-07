// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "interpolation" assists with interpolating variables
// from relevant OTel signals in URIs used for storage.

package interpolation

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNullContext(t *testing.T) {
	ictx := NullInterpolationContext()
	s, se := ictx.ConvertToString()
	assert.Equal(t, se, nil)
	assert.Equal(t, s, "null")

	assert.True(t, ictx.IsScalar())
	assert.True(t, ictx.IsNull())
	assert.False(t, ictx.IsObject())
	assert.False(t, ictx.IsArray())

	assert.False(t, ictx.ContainsField("foo"))
	assert.False(t, ictx.ContainsField("bar"))

	assert.False(t, ictx.ContainsKey("foo"))
	assert.False(t, ictx.ContainsKey("bar"))

	assert.False(t, ictx.ContainsIndex(0))
	assert.False(t, ictx.ContainsIndex(1))
	assert.False(t, ictx.ContainsIndex(-1))

	assert.Equal(t, ictx.Len(), 0)

	_, fe := ictx.GetField("foo")
	assert.NotEqual(t, fe, nil)

	_, ve := ictx.GetValue("foo")
	assert.NotEqual(t, ve, nil)

	_, ie := ictx.GetIndex(0)
	assert.NotEqual(t, ie, nil)
}

func TestEmptyContext(t *testing.T) {
	ictx := EmptyInterpolationContext()
	s, se := ictx.ConvertToString()
	assert.Equal(t, se, nil)
	assert.Equal(t, s, "")

	assert.True(t, ictx.IsScalar())
	assert.False(t, ictx.IsNull())
	assert.True(t, ictx.IsObject())
	assert.False(t, ictx.IsArray())

	assert.False(t, ictx.ContainsField("foo"))
	assert.False(t, ictx.ContainsField("bar"))

	assert.False(t, ictx.ContainsKey("foo"))
	assert.False(t, ictx.ContainsKey("bar"))

	assert.False(t, ictx.ContainsIndex(0))
	assert.False(t, ictx.ContainsIndex(1))
	assert.False(t, ictx.ContainsIndex(-1))

	assert.Equal(t, ictx.Len(), 0)

	_, fe := ictx.GetField("foo")
	assert.NotEqual(t, fe, nil)

	_, ve := ictx.GetValue("foo")
	assert.NotEqual(t, ve, nil)

	_, ie := ictx.GetIndex(0)
	assert.NotEqual(t, ie, nil)
}
