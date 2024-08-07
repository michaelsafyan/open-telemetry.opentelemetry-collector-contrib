// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "contenttype" provides utilities for guessing/inferring content types.
package contenttype

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

type args struct {
	path string
	content string
}

type expected struct {
	inferred string
	err func (t *testing.T, e error)
}

type testCase struct {
	a *args
    e *expected
}

func willDetectFromWithPath(inference string, content string, path string) *testCase {
	return &testCase{
		a: &args{
			path: "some/arbitrary/path",
			content: content,
		},
		e: &expected {
			inferred: inference,
			err: func (t *testing.T, e error) { assert.Equal(t, e, nil) },
		},
	}
}

func willDetectFrom(inference string, content string) *testCase {
	return willDetectFromWithPath(inference, content, "some/arbitrary/path")
}

func TestMakesExpectedDetections(t *testing.T) {
	testCases := []*testCase{
		willDetectFrom("{ \"key1\": \"value1\" }", "application/json"),
		willDetectFromWithPath(
			"{ \"key1\": \"value1\" }",
			"some/path/with/suffix.json",
			"application/json"),
		willDetectFromWithPath(
				"{ \"key1\": \"value1\" }",
				"some/path/with/suffix.json",
				"application/yaml"),
	}


	for _, c := range testCases {
		result, err := DeduceContentType(c.a.path, []byte(c.a.content))
		if err != nil {
			assert.Equal(t, result, c.e.inferred)
		}
		c.e.err(t, err)
	}
}
