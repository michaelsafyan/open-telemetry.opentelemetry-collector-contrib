// Package "interpolation" assists with interpolating variables
// from relevant OTel signals in URIs used for storage.
//
// The "contexts.go" file provides helpers for creating
// instances of the "InterpolationContext" object
package interpolation

import (
	"protoreflect"
)

// Implementation that represents an empty map.
type emptyContext struct{}

// emptyContext
func (c *emptyContext) IsScalar() bool                   { return false }
func (c *emptyContext) IsNull() bool                     { return false }
func (c *emptyContext) IsObject() bool                   { return true }
func (c *emptyContext) IsMap() bool                      { return true }
func (c *emptyContext) IsArray() bool                    { return true }
func (c *emptyContext) ContainsField(field string) bool  { return false }
func (c *emptyContext) ContainsKey(key string) bool      { return false }
func (c *emptyContext) ContainsIndex(index int) bool     { return false }
func (c *emptyContext) ConvertToString() (string, error) { return "", nil }
func (c *emptyContext) ConvertToBool() (bool, error)     { return false, nil }
func (c *emptyContext) ConvertToInt() (int, error)       { return 0, nil }
func (c *emptyContext) Len() int                         { return 0 }
func (c *emptyContext) GetField(name string) (InterpolationContext, error) {
	return nil, errors.New("no such field")
}
func (c *emptyContext) GetValue(name string) (InterpolationContext, error) {
	return nil, errors.New("no such key")
}
func (c *emptyContext) GetIndex(index int) (InterpolationContext, error) {
	return nil, errors.New("no such index")
}
