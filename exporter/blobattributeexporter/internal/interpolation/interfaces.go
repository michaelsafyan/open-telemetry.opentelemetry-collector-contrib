// Package "interpolation" assists with interpolating variables
// from relevant OTel signals in URIs used for storage.
//
// The "interfaces.go" file defines relevant interfaces for this package.
package interpolation

// InterpolationContext represents an object that supports
// recursive evaluation of its fields, properties, etc.
type InterpolationContext interface {
	// Whether this is a leaf in a hierarchy such that
	// it is not possible to resolve any further.
	IsScalar() bool

	// Whether this is a null value.
	IsNull() bool

	// Whether this is an object-like data structure.
	IsObject() bool

	// Whether this is a map-like data structure.
	IsMap() bool

	// Whether this is an array-like data structure.
	IsArray() bool

	// Whether the given field exists in this object.
	ContainsField(field string) bool

	// Whether the given key exists in this object.
	ContainsKey(key string) bool

	// Whether the given index exists in this object.
	ContainsIndex(index int) bool

	// Attempts to convert this object to a string.
	ConvertToString() (string, error)

	// Attempts to convert this object to a bool.
	ConvertToBool() (bool, error)

	// Attempts to convert this object to an int.
	ConvertToInt() (int, error)

	// The number of subfields. Valid only for
	// array and map data types.
	Len() int

	// Attempts to get the given field by name.
	// Valid only for objects.
	GetField(name string) (InterpolationContext, error)

	// Attempts to get the value for the given key.
	// Valid only for maps.
	GetValue(name string) (InterpolationContext, error)

	// Attempts to get the value for the given index.
	// Valid only for arrays.
	GetIndex(index int) (InterpolationContext, error)
}

// VariableResolver provides a simple interface for resolving
// the meaning of some kind of variable expression.
type VariableResolver interface {
	// Attempts to resolve the given variable lookup expression.
	Resolve(expr string) (string, error)
}

// Interpolator represents the component that combines
// a string with a InterpolationContext to perform variable
// substitutions within the supplied string.
type Interpolator interface {
	Interpolate(s string, ic InterpolationContext) (string, error)
}
