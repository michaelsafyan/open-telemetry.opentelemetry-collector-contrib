// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "interpolation" assists with interpolating variables
// from relevant OTel signals in URIs used for storage.
//
// The "interpolator.go" file provides the default implementation
// of the "Interpolator" interface that is used in this package.
package interpolation

import (
	"fmt"
	"strings"
)

// defaultInterpolator is an implementation of "Interpolator"
type defaultInterpolator struct{}

// Helper that uses a "VariableResolver" to do the interpolation.
func (d *defaultInterpolator) interpolateInternal(s string, r VariableResolver) (string, error) {
	var b strings.Builder
	var k strings.Builder
	var i int = 0
	var openCount int = 0
	for i < len(s) {
		// Handle escape sequence "$${"
		if s[i] == '$' && ((i + 1) < len(s)) && (s[i+1] == '$') {
			i += 2
			continue
		}

		// Handle open sequence "${"
		if s[i] == '$' && ((i + 1) < len(s)) && (s[i+1] == '{') {
			i += 2
			if openCount == 0 {
				k.Reset()
			}
			openCount += 1
		}

		// Handle close sequence "}"
		if s[i] == '}' {
			openCount -= 1
			if openCount == 0 {
				// The key is recursively interpolated to allow for dynamic resolution
				// as in something like "span.attribute.${env.SELECTED_ATTRIBUTE}".
				keyInterpolated, err := d.Interpolate(k.String(), r)
				if err != nil {
					return s, err
				}

				resolvedKey, err := r.Resolve(keyInterpolated)
				if err != nil {
					return s, err
				}
				b.WriteString(resolvedKey)
			}
			i++
			continue
		}

		// Hande all other characters
		if openCount > 0 {
			// When in a key, append to the key. We don't bother with
			// recursive resolution here, because that recursion is
			// handled when the larger key is closed above.
			k.WriteRune(s[i])
		} else {
			// Otherwise, append to the main output.
			b.WriteRune(s[i])
		}
		i++
	}

	if openCount > 0 {
		return s, fmt.Errorf("Mismatched '${' in %v", s)
	}

	return b.String(), nil
}

// Interpolate implements the "Interpolator.Interpolate" interface method.
func (d *defaultInterpolator) Interpolate(s string, ic InterpolationContext) (string, error) {
	r := NewResolver(ic)
	return d.interpolateInternal(s, r)
}

// New provides an interpolator instance.
func New() Interpolator {
	return &defaultInterpolator{}
}
