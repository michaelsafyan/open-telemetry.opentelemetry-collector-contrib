// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "interpolation" assists with interpolating variables
// from relevant OTel signals in URIs used for storage.
//
// The "contexts.go" file provides helpers for creating
// instances of the "InterpolationContext" object
package interpolation

import (
	"os"
	"strconv"
)

//***********************************************************
//* NULL
//***********************************************************

// Implementation that represents an empty map.
type nullContext struct{}

// nullContext
func (c *nullContext) IsScalar() bool                   { return true }
func (c *nullContext) IsNull() bool                     { return true }
func (c *nullContext) IsObject() bool                   { return false }
func (c *nullContext) IsMap() bool                      { return false }
func (c *nullContext) IsArray() bool                    { return false }
func (c *nullContext) ContainsField(field string) bool  { return false }
func (c *nullContext) ContainsKey(key string) bool      { return false }
func (c *nullContext) ContainsIndex(index int) bool     { return false }
func (c *nullContext) ConvertToString() (string, error) { return "null", nil }
func (c *nullContext) ConvertToBool() (bool, error)     { return false, nil }
func (c *nullContext) ConvertToInt() (int, error)       { return 0, nil }
func (c *nullContext) Len() int                         { return 0 }
func (c *nullContext) GetField(name string) (InterpolationContext, error) {
	return nil, errors.New("Cannot dereference null value.")
}
func (c *nullContext) GetValue(name string) (InterpolationContext, error) {
	return nil, errors.New("Cannot dereference null value.")
}
func (c *nullContext) GetIndex(index int) (InterpolationContext, error) {
	return nil, errors.New("Cannot dereference null value.")
}

// Simple factory
func NullInterpolationContext() InterpolationContext {
	return &nullContext{}
}

//***********************************************************
//* EMPTY
//***********************************************************

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
	return nil, fmt.Errorf("No such field: %v", name)
}
func (c *emptyContext) GetValue(name string) (InterpolationContext, error) {
	return nil, fmt.Errorf("No such key: %v", name)
}
func (c *emptyContext) GetIndex(index int) (InterpolationContext, error) {
	return nil, fmt.Errorf("No such index: %v", index)
}

// Simple factory
func EmptyInterpolationContext() InterpolationContext {
	return &emptyContext{}
}

//***********************************************************
//* MERGE
//***********************************************************

// Implementation that represents a merge of two contexts.
type mergeContext struct {
	a InterpolationContext
	b InterpolationContext
}

// mergeContext
func (c *mergeContext) IsScalar() bool { return false }
func (c *mergeContext) IsNull() bool   { return false }
func (c *mergeContext) IsObject() bool {
	a := c.a
	b := c.b
	return a.IsObject() || b.IsObject()
}

func (c *mergeContext) IsMap() bool {
	a := c.a
	b := c.b
	return a.IsMap() || b.IsMap()
}

func (c *mergeContext) IsArray() bool {
	a := c.a
	b := c.b
	return a.IsArray() || b.IsArray()
}

func (c *mergeContext) ContainsField(field string) bool {
	a := c.a
	b := c.b
	return a.ContainsField(field) || b.ContainsField(b)
}

func (c *mergeContext) ContainsKey(key string) bool {
	a := c.a
	b := c.b
	return a.ContainsKey(field) || b.ContainsKey(b)
}

func (c *mergeContext) ContainsIndex(index int) bool {
	a := c.a
	b := c.b
	if a.IsArray() && b.IsArray() {
		return a.ContainsIndex(index) || b.ContainsIndex(index-a.Len())
	}
	if a.IsArray() {
		return a.ContainsIndex(index)
	}
	if b.IsArray() {
		return b.ContainsIndex(index)
	}
	return false
}

func (c *mergeContext) ConvertToString() (string, error) {
	a := c.a
	b := c.b
	aString, erra := a.ConvertToString()
	if erra != nil {
		return "", erra
	}
	bString, errb := b.Conert
	if errb != nil {
		return "", errb
	}
	return fmt.Sprintf("Merge(%v, %v)", aString, bString), nil
}

func (c *mergeContext) ConvertToBool() (bool, error) {
	return c.Len() > 0, nil
}

func (c *mergeContext) ConvertToInt() (int, error) {
	return 0, errors.New("Cannot convert a merged context to an integer.")
}

func (c *mergeContext) Len() int {
	return c.a.Len() + c.b.Len()
}

func (c *mergeContext) GetField(name string) (InterpolationContext, error) {
	aentry, aerr := a.GetField(name)
	if aerr == nil {
		return aentry, nil
	}
	bentry, berr := b.GetField(name)
	if berr == nil {
		return bentry, nil
	}
	return nil, fmt.Errorf("No such field: %v", name)
}

func (c *mergeContext) GetValue(name string) (InterpolationContext, error) {
	aentry, aerr := a.GetValue(name)
	if aerr == nil {
		return aentry, nil
	}
	bentry, berr := b.GetValue(name)
	if berr == nil {
		return bentry, nil
	}
	return nil, fmt.Errorf("No such key: %v", name)
}

func (c *mergeContext) GetIndex(index int) (InterpolationContext, error) {
	a := c.a
	b := c.b
	if a.IsArray() && b.IsArray() {
		aentry, aerr := a.GetIndex(index)
		if aerr == nil {
			return aentry, nil
		}
		bentry, berr := b.GetIndex(index - a.Len())
		if berr == nil {
			return bentry, nil
		}
		return nil, fmt.Errorf("No such index: %v", index)
	}
	if a.IsArray() {
		return a.GetIndex(index)
	}
	if b.IsArray() {
		return b.GetIndex(index)
	}
	return nil, fmt.Errorf("No such index: %v", index)
}

// Simple factory
func MergeInterpolationContexts(
	a InterpolationContext,
	b InterpolationContext) (InterpolationContext, error) {
	if a.IsScalar() || b.IsScalar() {
		return nil, errors.New("Cannot merge scalar values.")
	}
	return &mergeContext{
		a: a,
		b: b,
	}, nil
}

//***********************************************************
//* ENVIRONMENT VARIABLES
//***********************************************************

// Implementation that represents the entire environment.
type osEnvContext struct{}

// Implementation that represents a single key in the environment.
type osEnvVariableContext struct {
	key string
}

// osEnvVariableContext
func (c *osEnvVariableContext) IsScalar() bool                   { return true }
func (c *osEnvVariableContext) IsNull() bool                     {
 _, present := os.LookupEnv(c.key)
 return !present
}

func (c *osEnvVariableContext) IsObject() bool                   { return false }

func (c *osEnvVariableContext) IsMap() bool                      {
	// TODO: maybe say yes for keys that are known to contain map-like data
	return false
}

func (c *osEnvVariableContext) IsArray() bool                    {
	// TODO: maybe say yes for keys that are known to contain array-like data (e.g. "PATH")
	return false
}

func (c *osEnvVariableContext) ContainsField(field string) bool  { return false }
func (c *osEnvVariableContext) ContainsKey(key string) bool      { return false }
func (c *osEnvVariableContext) ContainsIndex(index int) bool     { return false }

func (c *osEnvVariableContext) ConvertToString() (string, error) {
	return os.GetEnv(c.key), nil
}

func stringToBool(s string) (bool, error) {
	toCompare := strings.ToLower(s)
	falseValues := {
		"",
		"0",
		"f",
		"false",
		"no"
	}
	trueValues := {
		"1",
		"t",
		"true",
		"yes"
	}
	for fv := range falseValues {
		if toCompare == fv {
			return false, nil
		}
	}
	for tv := range trueValues {
		if toCompare == tv {
			return true, nil
		}
	}
	return nil, fmt.Errorf("Cannot convert to bool: %v", s)
}

func (c *osEnvVariableContext) ConvertToBool() (bool, error)     {
	value := os.GetEnv(c.key)
	return stringToBool(value)
}

func (c *osEnvVariableContext) ConvertToInt() (int, error)       {
	value := os.GetEnv(c.key)
	if value == "" {
		return 0, nil
	}
	return strconv.Atoi(value)
}

func (c *osEnvVariableContext) Len() int                         {
	// TODO: special handling for array-like or map-like env keys?
	// For example, should this split "PATH" to give a true count?

	return 1  // 1 object contained, itself
}

func (c *osEnvVariableContext) GetField(name string) (InterpolationContext, error) {
	return nil, errors.New("Cannot get field member of an env var.")
}

func (c *osEnvVariableContext) GetValue(name string) (InterpolationContext, error) {
	// TODO: should this handle cases like "key1=value1;key2=value2" ?
	return nil, errors.New("Cannot get map element on an env var.")
}

func (c *osEnvVariableContext) GetIndex(index int) (InterpolationContext, error) {
	// TODO: should this handle cases like "PATH" ?
	return nil, errors.New("Cannot get an index of an env var.")
}

// osEnvContext
func (c *osEnvContext) IsScalar() bool                   { return false }
func (c *osEnvContext) IsNull() bool                     { return false }
func (c *osEnvContext) IsObject() bool                   { return false }
func (c *osEnvContext) IsMap() bool                      { return true }
func (c *osEnvContext) IsArray() bool                    { return false }

func (c *osEnvContext) ContainsField(field string) bool  { return false }
func (c *osEnvContext) ContainsKey(key string) bool      {
	_, present := os.LookupEnv(key)
	return present
}

func (c *osEnvContext) ContainsIndex(index int) bool     { return false }

func (c *osEnvContext) ConvertToString() (string, error) {
	return strings.Join(os.Environ(), "\n"), nil
}

func (c *osEnvContext) ConvertToBool() (bool, error)     {
	return false, errors.New("Cannot convert env to bool.")
}

func (c *osEnvContext) ConvertToInt() (int, error)       {
	return 0, errors.New("Cannot convert env to int.")
}

func (c *osEnvContext) Len() int                         {
	return len(os.Environ())
}

func (c *osEnvContext) GetField(name string) (InterpolationContext, error) {
	return nil, fmt.Errorf("No such field: %v", name)
}
func (c *osEnvContext) GetValue(name string) (InterpolationContext, error) {
	return &osEnvVariableContext{ key: name }, nil
}
func (c *osEnvContext) GetIndex(index int) (InterpolationContext, error) {
	return nil, fmt.Errorf("No such index: %v", index)
}

// Simple factory
func OsEnvContext() InterpolationContext {
	return &osEnvContext{}
}
