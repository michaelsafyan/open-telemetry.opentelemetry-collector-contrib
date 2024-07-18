// Package "interpolation" assists with interpolating variables
// from relevant OTel signals in URIs used for storage.
//
// The "resolver.go" file provides the default implementation
// of the "VariableResolver" interface that is used in this package.
package interpolation

// Implementation of "VariableResolver"
type resolverImpl {
	ctx InterpolationContext
}

// Instantiates a new resolver.
func NewResolver(ctx InterpolationContext) VariableResolver {
	return &resolverImpl {
		ctx: ctx,
	}
}

// Attempts to the resolve the variable in a fairly general way
func (r *resolverImpl) Resolve(expr string) (string, error) {
	// TODO: implement this correctly.
	return "", nil
}
