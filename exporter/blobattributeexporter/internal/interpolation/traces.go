// Package "interpolation" assists with interpolating variables
// from relevant OTel signals in URIs used for storage.
//
// The "traces.go" file provides implementations of "VariableResolver"
// for different concepts related to the "trace" signal.
package interpolation

import "os"
import "reflect"
import "go.opentelemetry.io/collector/pdata/ptrace"
import "go.opentelemetry.io/collector/pdata/pcommon"

// "spanResolver" implements the "VariableResolver" interface
// for a single span contained in a "ptrace.Traces" structure.
type spanResolver struct {
	resource *ptrace.ResourceSpans
	scope *ptrace.ScopeSpans
	span *ptrace.Span
}

// NewSpanResolver constructs a span resolver from the given parameters.
func NewSpanResolver(
	traces *ptrace.Traces,
	resourceIndex int,
	scopeIndex int,
	spanIndex int) (*spanReference, error) {
 resources := traces.GetResourceSpans()
 if resourceIndex < 0 || resourceIndex >= resources.Len() {
	 return nil, fmt.Errorf("Invalid resourceIndex: %v, valid values are: [0, %v].", resourceIndex, resources.Len() - 1)
 }

 resource := resources.At(resourceIndex)
 scopes := resources.ScopeSpans()
 if scopeIndex < 0 || scopeIndex >= scopes.Len() {
	return nil, fmt.Errorf("Invalid scopeIndex: %v, valid values are: [0, %v].", scopeIndex, scopes.Len() - 1)
 }

 scope := scopes.At(scopeIndex)
 spans := scope.Spans()
 if spanIndex < 0 || spanIndex >= spans.Len() {
	return nil, fmt.Errorf("Invalid spanIndex: %v, valid values are: [0, %v].", spanIndex, spans.Len() - 1)
 }

 return &spanResolver{
	 resource: resource,
	 scope: scope,
	 span: span,
 }, nil
}

// "stringify" is a helper of "Resolve" used to convert interfaces to strings.
func stringify(obj interface{}) string {
	objType := reflect.TypeOf(obj)

	// Attempts to call the "AsString()" function
	{
		asStringMethod, ok := objType.MethodByName("AsString")
		if ok {
			objAsValue := reflect.ValueOf(obj)
			args = []Value{objAsValue}
			results := stringMethod.Call(args)
			if len(results) == 1 {
				return results[0].String()
			}
		}
	}

	// Attempts to call the "String()" function
	{
		stringMethod, ok := objType.MethodByName("String")
		if ok {
			objAsValue := reflect.ValueOf(obj)
			args = []Value{objAsValue}
			results := stringMethod.Call(args)
			if len(results) == 1 {
				return results[0].String()
			}
		}
	}

	return fmt.Sprintf("%v", obj)
}

// "resolveLen" is a helper of "resolveObj" below for the case where "len(...)" is used.
func resolveLen(obj interface{}) (int, error) {
	objType := reflect.TypeOf(obj)
	lenMethod, ok := objType.MethodByName("Len")
	if ok {
		objAsValue := reflect.ValueOf(obj)
		args = []Value{objAsValue}
		results := lenMethod.Call(args)
		if len(results) == 1 && results[0].CanInt() {
			return results[0].Int(), nil
		}
	}

	return -1, fmt.Errorf("Could not compute len() on %v", obj)
}

// "resolveEnvVar" is a helper of "resolveObj" for the case where "${env.FOO}" is used.
func resolveEnvVar(key string) (string, error) {
	val, ok := os.LookupEnv(key)
	if ok {
		return val, nil
	}
	return nil, fmt.Errorf("Environment variable %v not set.", key)
}

// "resolveReflectively" is a helper of "resolveObj" for general-purpose resolution.
func resolveReflectively(obj interface{}, key string) (interface{}, error) {
	// TODO: implement a general-purpose resolution mechanism that supports
	// Protobuf reflection where available and general Go reflection otherwise.
	return nil, fmt.Errorf("Could not resolve: %v from %v; reflection-based resolution not yet implemented.", key, obj)
}

// Interface that aligns with a subset of the functionality of "pcommon.Map". We
// extract out this interface to allow for processing a combined attribute map.
type attributesMapInterface {
	func Get(key string) (pcommon.Value, bool)
}

// Implementation of the attributesMapInterface for a combined attributes map.
type combinedAttributesMap struct {
	spanAttributes pcommon.Map
	resourceAttributes pcommon.Map
	scopeAttributes pcommon.Map
}
func (c *combinedAttributesMap) Get(key string) (pcommon.Value, bool) {
	v1, ok1 := c.spanAttributes.Get(key)
	if ok1 {
		return v1, true
	}

	v2, ok2 := c.resourceAttributes.Get(key)
	if ok2 {
		return v2, true
	}

	v3, ok3 := c.scopeAttributes.Get(key)
	if ok3 {
		return v3, true
	}

	return nil, false
}

// "resolveAttribute" is a helper of "resolveObj" for various attribute maps
func resolveAttribute(attributesMap attributesMapInterface, key string) (interface{}, error) {
  result, ok := attributesMap.Get(key)
  if ok {
	  return result, nil
  }
  return nil, fmt.Errorf("Could not find key %v in %v", key, attributesMap)
}

// "resolveObj" is a helper for "Resolve" below which can resolve to objects
// other than raw strings. This allows for the implementation of utility
// functions like "len(...)" to be used in the resolution.
func (s *spanResolver) resolveObj(key string) (interface{}, error) {
  // Remove extraneous whitespace around the key
  keyStripped := strings.TrimSpace(key)

  // Check to see if this is a "len()" call.
  if strings.HasPrefix(keyStripped, "len(") && strings.HasSuffix(keyStripped, ")") {
	  innerKey := strings.TrimSuffix(strings.TrimPrefix(keyStripped, "len("), ")")
	  innerValue, err := s.resolveObj(key)
	  if err != nil {
		  return nil, err
	  }
	  return resolveLen(innerValue)
  }

  // Check to see if this is a "." or "$." reference to the current context.
  if strings.HasPrefix(keyStripped, ".") {
	  rest := strings.TrimPrefix(keyStripped, ".")
	  return s.resolveObj(rest)
  }
  if strings.HasPrefix(keyStripped, "$.") {
	rest := strings.TrimPrefix(keyStripped, "$.")
	return s.resolveObj(rest)
  }

  // Check to see if this is a reference to an environment variable.
  if strings.HasPrefix(keyStripped, "env.") {
	  rest := strings.TrimPrefix(keyStripped, "env.")
	  return resolveEnvVar(rest)
  }

  // Check for commonly referenced properties to short circuit more general,
  // reflection-based resolution of object properties.
  if keyStripped == "name" {
	  return s.span.Name(), nil
  }
  if keyStripped == "trace_id" ||
	 keyStripped == "traceId" ||
	 keyStripped == "span.trace_id" ||
	 keyStripped == "span.traceId" {
	return s.span.TraceID().String(), nil
  }
  if keyStripped == "span_id" ||
	 keyStripped == "spanId" ||
	 keyStripped == "span.span_id" ||
	 keyStripped == "span.spanId" {
	return s.span.SpanID().String(), nil
  }
  if keyStripped == "parent_span_id" ||
	keyStripped == "parentSpanId" ||
	keyStripped == "span.parent_span_id" ||
    keyStripped == "span.parentSpanId" {
	return s.span.ParentSpanID().String(), nil
  }
  if strings.HasPrefix(keyStripped, "attribute.") {
	  rest := strings.TrimPrefix(keyStripped, "attribute.")
	  amap := &combinedAttributesMap{
		  spanAttributes: s.span.Attributes(),
		  resourceAttributes: s.resource.Attributes(),
		  scopeAttributes: s.scope.Attributes()
	  }
	  return resolveAttribute(amap, rest)
  }
  if strings.HasPrefix(keyStripped, "span.attribute.") {
	rest := strings.TrimPrefix(keyStripped, "span.attribute.")
	return resolveAttribute(s.span.Attributes(), rest)
  }
  if strings.HasPrefix(keyStripped, "resource.attribute.") {
	rest := strings.TrimPrefix(keyStripped, "resource.attribute.")
	return resolveAttribute(s.resource.Attributes(), rest)
  }
  if strings.HasPrefix(keyStripped, "scope.attribute.") {
	rest := strings.TrimPrefix(keyStripped, "scope.attribute.")
	return resolveAttribute(s.span.Attributes(), rest)
  }
  if strings.HasPrefix(keyStripped, "instrumentation_scope.attribute.") {
	rest := strings.TrimPrefix(keyStripped, "instrumentation_scope.attribute.")
	return resolveAttribute(s.span.Attributes(), rest)
  }
  if strings.HasPrefix(keyStripped, "instrumentationScope.attribute.") {
	rest := strings.TrimPrefix(keyStripped, "instrumentationScope.attribute.")
	return resolveAttribute(s.span.Attributes(), rest)
  }

  // Resolve other properties reflectively
  if strings.HasPrefix(keyStripped, "span.") {
	  rest := strings.TrimPrefix(keyStripped, "span.")
	  resolveReflectively(s.span, rest)
  }
  if strings.HasPrefix(keyStripped, "resource.") {
	rest := strings.TrimPrefix(keyStripped, "resource.")
	resolveReflectively(s.resource, rest)
  }
  if strings.HasPrefix(keyStripped, "scope.") {
	rest := strings.TrimPrefix(keyStripped, "scope.")
	resolveReflectively(s.scope, rest)
  }
  if strings.HasPrefix(keyStripped, "instrumentation_scope.") {
	rest := strings.TrimPrefix(keyStripped, "instrumentation_scope.")
	resolveReflectively(s.scope, rest)
  }
  if strings.HasPrefix(keyStripped, "instrumentationScope.") {
	rest := strings.TrimPrefix(keyStripped, "instrumentationScope.")
	resolveReflectively(s.scope, rest)
  }

  // Try to resolve other properties reflectively from the "span"
  // level object, even without an explicit "span.". However, if this
  // fails, the message will be clearer if we reference the current
  // context rather than referencing the "span" sub-object.
  result, err := resolveReflectively(s.span, keyStripped)
  if err == nil {
	  return result, nil
  }
  return nil, fmt.Errof("Failed to resolve %v in %v", keyStripped, s.String())
}

// "Resolve" implements "VariableResolver.Resolve".
func (s *spanResolver) Resolve(key string) (string, error) {
	result, err := s.resolveObj(key)
	if err != nil {
		return "", err
	}
	return stringify(result), nil
}

// "String" provides a debug string for this object.
func (s *spanResolver) String() string {
	return fmt.Sprintf(
		"{\n\tspan: %v,\n\tresource: %v,\n\tscope: %v,\n}",
		s.span.String(),
		s.resource.String(),
		s.scope.String())
}
