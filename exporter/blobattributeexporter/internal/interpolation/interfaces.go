// Package "interpolation" assists with interpolating variables
// from relevant OTel signals in URIs used for storage.
//
// The "interfaces.go" file defines relevant interfaces for this package.
package interpolation

// VariableResolver provides a mechanism for resolving
// "${variables_like_this}" contained in a string.
type VariableResolver interface {
	// Resolve the given key. The key does not include
	// the "${" prefix nor the "}" suffix.
	Resolve(key string) (string, error)
}

// Interpolator represents the component that combines
// a string with a VariableResolver to perform variable
// substitutions within the supplied string.
type Interpolator interface {
	Interpolate(s string, r VariableResolver) (string, error)
}
