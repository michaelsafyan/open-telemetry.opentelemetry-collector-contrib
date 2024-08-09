// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "blobattributeuploadconnector" provides a connector that writes
// certain specified attributes to a blob storage backend.
//
// The file "traces.go" file provides the logic for the traces signal type.
package blobattributeuploadconnector

import (
	"fmt"
	"context"
	"hash/maphash"

	"go.uber.org/zap"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/connector"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/pcommon"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/contexts/ottlspan"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/contexts/ottlspanevent"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/ottlfuncs"

	"github.com/open-telemetry/opentelemetry-collector-contrib/connector/blobattributeuploadconnector/internal/backend"
	"github.com/open-telemetry/opentelemetry-collector-contrib/connector/blobattributeuploadconnector/internal/contenttype"
	"github.com/open-telemetry/opentelemetry-collector-contrib/connector/blobattributeuploadconnector/internal/foreignattr"
)

type passThroughTracesConnector struct {
	nextConsumer consumer.Traces
	component.StartFunc
	component.ShutdownFunc
}

func (c *passThroughTracesConnector) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	return c.nextConsumer.ConsumeTraces(ctx, td)
}

func (c *passThroughTracesConnector) Capabilities() consumer.Capabilities {
    return consumer.Capabilities{MutatesData: false}
}

type spanReference struct {
	resource      pcommon.Resource
	scope         pcommon.InstrumentationScope
	span          ptrace.Span
	scopeSpans    ptrace.ScopeSpans
	resourceSpans ptrace.ResourceSpans
	ottlCtx       ottlspan.TransformContext
}

func (s *spanReference) traceID() pcommon.TraceID {
	return s.span.TraceID()
}

type spanEventReference struct {
	span    *spanReference
	index   int
	event   ptrace.SpanEvent
	ottlCtx ottlspanevent.TransformContext
}

func (se *spanEventReference) traceID() pcommon.TraceID {
	return se.span.traceID()
}

type attributeRuleMap struct {
	attributeNameToRule map[string]*AttributeConfigRule
}

func newAttributeRuleMap() *attributeRuleMap {
	return &attributeRuleMap{
		attributeNameToRule: make(map[string]*AttributeConfigRule),
	}
}

func (arm *attributeRuleMap) add(acr *AttributeConfigRule) error {
	existing, present := arm.attributeNameToRule[acr.Match.Key]
	if present {
		return fmt.Errorf("rule %v conflicts with existing rule %v; both match on attribute %v",
		   acr.Name,
		   existing.Name,
		   acr.Match.Key)
	}
	arm.attributeNameToRule[acr.Match.Key] = acr
	return nil
}

func (arm *attributeRuleMap) get(k string) *AttributeConfigRule {
	existing, present := arm.attributeNameToRule[k]
	if present {
		return existing
	}
	return nil
}

type eventAttributeRules struct {
	allEvents *attributeRuleMap
	eventNameToRuleMap map[string]*attributeRuleMap
}

func newEventAttributeRules() *eventAttributeRules {
	return &eventAttributeRules{
		allEvents: newAttributeRuleMap(),
		eventNameToRuleMap: make(map[string]*attributeRuleMap),
	}
}

func (ear *eventAttributeRules) add(secg *SpanEventsConfigGroup) error {
	if secg.Attributes == nil {
		return nil
	}

	var mapsToUpdate = []*attributeRuleMap{}
	if secg.EventName == nil || secg.EventName.MatchAll {
		mapsToUpdate = append(mapsToUpdate, ear.allEvents) 
	} else {
		for _, name := range secg.EventName.MatchIfAnyEqualTo {
			existing, present := ear.eventNameToRuleMap[name]
			if present {
				mapsToUpdate = append(mapsToUpdate, existing)
			} else {
				newMap := newAttributeRuleMap()
				ear.eventNameToRuleMap[name] = newMap
				mapsToUpdate = append(mapsToUpdate, existing)
			}
		}
	}

	for _, rule := range secg.Attributes.Rule {
		for _, m := range mapsToUpdate {
			if err := m.add(rule) ; err != nil {
				return err
			}
		}
	}

	return nil
}

type applicableEventAttributeRules struct {
	values []*attributeRuleMap
}

func (ear *eventAttributeRules) get(eventName string) *applicableEventAttributeRules {
	existing, present := ear.eventNameToRuleMap[eventName]
	if present {
		return &applicableEventAttributeRules{
			values: []*attributeRuleMap{
				existing,
				ear.allEvents,
			},
		}
	}

	return &applicableEventAttributeRules{
		values: []*attributeRuleMap{ear.allEvents},
	}
}

func (aear *applicableEventAttributeRules) get(attributeName string) *AttributeConfigRule {
	for _, m := range aear.values {
		entry := m.get(attributeName)
		if entry != nil {
			return entry
		}
	}
	return nil
}

type matchedAttribute struct {
	key string
	value pcommon.Value
	rule *AttributeConfigRule
}

type matchedAttributeList struct {
	items []*matchedAttribute
}

func newMatchedAttributeList() *matchedAttributeList {
	return &matchedAttributeList{
		items: []*matchedAttribute{},
	}
}

func (mal *matchedAttributeList) add(ma *matchedAttribute) {
	mal.items = append(mal.items, ma)
}

type tracesToTracesImpl struct {
	settings connector.Settings
	nextConsumer consumer.Traces
	spanAttributes *attributeRuleMap
	spanEvents *eventAttributeRules
	backendRegistry backend.Registry
	spanFuncs map[string]ottl.Factory[ottlspan.TransformContext]
	spanEventFuncs map[string]ottl.Factory[ottlspanevent.TransformContext]
	seed maphash.Seed
	component.StartFunc
	component.ShutdownFunc
}

func (tracesImpl *tracesToTracesImpl) shouldSampleAttributeInTrace(m *matchedAttribute, traceID pcommon.TraceID) bool {
	if m.rule.Action == nil  {
		return false
	}
	if m.rule.Action.Sampling == nil {
		return true
	}
	if m.rule.Action.Sampling.Enabled == false {
		return true
	}

	samplePercent := m.rule.Action.Sampling.Percent
	hashVal := maphash.Bytes(tracesImpl.seed, []byte(traceID[:]))
	mod100 := int(hashVal % 100)
	return mod100 < samplePercent
}

func (tracesImpl *tracesToTracesImpl) shouldSampleSpanEventAttribute(se *spanEventReference, m *matchedAttribute) bool {
	return tracesImpl.shouldSampleAttributeInTrace(m, se.traceID()) 
}

func (tracesImpl *tracesToTracesImpl) shouldSampleSpanAttribute(s *spanReference, m *matchedAttribute) bool {
	return tracesImpl.shouldSampleAttributeInTrace(m, s.traceID()) 
}

func (tracesImpl *tracesToTracesImpl) interpolateSpanEvent(
	ctx context.Context,
	pattern string,
	se *spanEventReference) (string, error) {
 // TODO: ...
 return "", nil
}

func (tracesImpl *tracesToTracesImpl) interpolateSpan(
	ctx context.Context,
	pattern string,
	s *spanReference) (string, error) {
  // TODO: ...
  return "", nil
}

func (tracesImpl *tracesToTracesImpl) interpolateFuncForSpanEvent(se *spanEventReference) func(context.Context, string) (string, error) {
	return func(ctx context.Context, pattern string) (string, error) {
		return tracesImpl.interpolateSpanEvent(ctx, pattern, se)
	}
}

func (tracesImpl *tracesToTracesImpl) interpolateFuncForSpan(s *spanReference) func(context.Context, string) (string, error) {
	return func(ctx context.Context, pattern string) (string, error) {
		return tracesImpl.interpolateSpan(ctx, pattern, s)
	}
}

func (tracesImpl *tracesToTracesImpl) computeDestinationUriForSpanEvent(
	ctx context.Context,
	se *spanEventReference,
    m *matchedAttribute) (string, error) {
  if m.rule.Action == nil {
	  return "", fmt.Errorf("missing 'action' in rule %v", m.rule.Name)
  }
  if m.rule.Action.Upload == nil {
	return "", fmt.Errorf("missing 'action.upload' in rule %v", m.rule.Name)
  }

  destinationUriPattern := m.rule.Action.Upload.DestinationUri
  if len(destinationUriPattern) == 0 {
	return "", fmt.Errorf("empty 'action.upload.destination_uri' in rule %v", m.rule.Name)
  }

  return tracesImpl.interpolateSpanEvent(ctx, destinationUriPattern, se)
}

func (tracesImpl *tracesToTracesImpl) computeDestinationUriForSpan(
	ctx context.Context,
	s *spanReference,
    m *matchedAttribute) (string, error) {
 if m.rule.Action == nil {
	return "", fmt.Errorf("missing 'action' in rule %v", m.rule.Name)
 }
 if m.rule.Action.Upload == nil {
	return "", fmt.Errorf("missing 'action.upload' in rule %v", m.rule.Name)
 }

 destinationUriPattern := m.rule.Action.Upload.DestinationUri
 if len(destinationUriPattern) == 0 {
	return "", fmt.Errorf("empty 'action.upload.destination_uri' in rule %v", m.rule.Name)
 }

 return tracesImpl.interpolateSpan(ctx, destinationUriPattern, s)
}

func computeDataEncoding(value pcommon.Value) ([]byte, error) {
  // TODO: ...
 return []byte{}, nil
}


func (tracesImpl *tracesToTracesImpl) computeContentTypeCommon(
	ctx context.Context,
	m *matchedAttribute,
	interplateFunc func(context.Context, string) (string, error),
	uri string,
	data []byte) (string, error) {
 if m.rule.Action == nil {
  return "", fmt.Errorf("missing 'action' in rule %v", m.rule.Name)
 }
 
 if m.rule.Action.Upload == nil {
  return "", fmt.Errorf("missing 'action.upload' in rule %v", m.rule.Name)
 }

 uploadCfg := m.rule.Action.Upload
 contentTypeCfg := uploadCfg.ContentType
 if contentTypeCfg == nil ||
    ((contentTypeCfg != nil ) && (contentTypeCfg.Automatic != nil) && (contentTypeCfg.Automatic.Enabled)) {
   return contenttype.DeduceContentType(uri, data)
 }

 if len(contentTypeCfg.StaticValue) != 0 {
	 return contentTypeCfg.StaticValue, nil
 }

 if contentTypeCfg.Extraction != nil {
	 return interplateFunc(ctx, contentTypeCfg.Extraction.Expression)
 }

 return "", fmt.Errorf("unrecognized content type configuration for rule %v", m.rule.Name)
}

func (tracesImpl *tracesToTracesImpl) computeContentTypeForSpanEventAttribute(
	ctx context.Context,
	se *spanEventReference,
	m *matchedAttribute,
	uri string,
	data []byte) (string, error) {
  interpolateFunc := tracesImpl.interpolateFuncForSpanEvent(se)
  return tracesImpl.computeContentTypeCommon(
	  ctx,
	  m,
	  interpolateFunc,
	  uri,
	  data)
}

func (tracesImpl *tracesToTracesImpl) computeContentTypeForSpanAttribute(
	ctx context.Context,
	s *spanReference,
	m *matchedAttribute,
	uri string,
	data []byte) (string, error) {
 interpolateFunc := tracesImpl.interpolateFuncForSpan(s)
 return tracesImpl.computeContentTypeCommon(
	ctx,
	m,
	interpolateFunc,
	uri,
	data)
}

func (tracesImpl *tracesToTracesImpl) addMetadataLabels(
	ctx context.Context,
	m *matchedAttribute,
	interpolateFunc func(context.Context, string) (string, error),
	output map[string]string) error {
 // TODO: ...
 return nil
}

func (tracesImpl *tracesToTracesImpl) computeUploadMetadataForSpanEvent(
	ctx context.Context,
	se *spanEventReference,
    m *matchedAttribute) (map[string]string, error) {
  result := map[string]string{
	  "trace_id": se.span.span.TraceID().String(),
	  "span_id": se.span.span.SpanID().String(),
	  "event_index": fmt.Sprintf("%v", se.index),
	  "event_name": se.event.Name(),
	  "event_attribute": m.key,
  }

  interpolateFunc := tracesImpl.interpolateFuncForSpanEvent(se)
  err := tracesImpl.addMetadataLabels(ctx, m, interpolateFunc, result)
  if err != nil {
	  return nil, err
  }

  return result, nil
}

func (tracesImpl *tracesToTracesImpl) computeUploadMetadataForSpan(
	ctx context.Context,
	s *spanReference,
    m *matchedAttribute) (map[string]string, error) {
 result := map[string]string{
	"trace_id": s.span.TraceID().String(),
	"span_id": s.span.SpanID().String(),
	"span_attribute": m.key,
 }

 interpolateFunc := tracesImpl.interpolateFuncForSpan(s)
 err := tracesImpl.addMetadataLabels(ctx, m, interpolateFunc, result)
 if err != nil {
	 return nil, err
 }

 return result, nil
}

type pendingUpload struct {
	storageBackend backend.BlobStorageBackend
	key string
	data []byte
	destinationUri string
	contentType string
	metadataLabels map[string]string
}

func (tracesImpl *tracesToTracesImpl) scheduleUpload(
	ctx context.Context,
	pending *pendingUpload) error {
  // TODO: ...
  return nil
}

type foreignAttrRef struct {
	value pcommon.Value
}

func setInMap(m pcommon.Map, key string, item *foreignAttrRef) {
	item.value.CopyTo(m.PutEmpty(key))
}

func (tracesImpl *tracesToTracesImpl) createForeignAttr(uri string, contentType string) *foreignAttrRef {
	if len(contentType) == 0 {
		return &foreignAttrRef{
			value: foreignattr.FromUri(uri),
		}
	}
	return &foreignAttrRef {
		value: foreignattr.FromUriWithContentType(uri, contentType),
	}
}

func (tracesImpl *tracesToTracesImpl) processSingleMatchedSpanEventAttribute(
	ctx context.Context,
	se *spanEventReference,
    m *matchedAttribute) (*foreignAttrRef, error) {
	if (!tracesImpl.shouldSampleSpanEventAttribute(se, m)) {
		return nil, nil
	}

	destinationUri, destinationUriErr := tracesImpl.computeDestinationUriForSpanEvent(ctx, se, m)
	if destinationUriErr != nil {
		tracesImpl.settings.Logger.Error(
			"Could not create destination URI for span event attribute",
			zap.String("attributeKey", m.key),
			zap.String("configRuleName", m.rule.Name),
		    zap.NamedError("error", destinationUriErr))
		return nil, destinationUriErr
	}

	b, berr := tracesImpl.backendRegistry.GetBackendForURI(destinationUri)
	if berr != nil {
		tracesImpl.settings.Logger.Error(
			"Could not find suitable storage backend for destination URI",
			zap.String("destinationUri", destinationUri),
		    zap.NamedError("error", berr))
		return nil, berr
	}

	d, derr := computeDataEncoding(m.value)
	if derr != nil {
		return nil, derr
	}

	contentType, contentTypeErr := tracesImpl.computeContentTypeForSpanEventAttribute(ctx, se, m, destinationUri, d)
	if contentTypeErr != nil {
		return nil, contentTypeErr
	}

	pending := &pendingUpload{
		storageBackend: b,
		key: m.key,
		data: d,
		destinationUri: destinationUri,
		contentType: contentType,
	}

	err := tracesImpl.scheduleUpload(ctx, pending)
	if err != nil {
		return nil, err
	}

	return tracesImpl.createForeignAttr(destinationUri, contentType), nil
}

func (tracesImpl *tracesToTracesImpl) consumeSpanEvent(ctx context.Context, se *spanEventReference) error {
	name := se.event.Name()
	rulesResolver := tracesImpl.spanEvents.get(name)
	m := se.event.Attributes()
	toProcess := newMatchedAttributeList()
	m.Range(func(k string, v pcommon.Value) bool { 
		rule := rulesResolver.get(k)
		if rule == nil {
			return true
		}

		matchedAttr := &matchedAttribute{
			key: k,
			value: v,
			rule: rule,
		}

		tracesImpl.settings.Logger.Debug("Found matching span event attribute", zap.String("attributeKey", k))
		toProcess.add(matchedAttr)
		return true
	})

	for _, entry := range toProcess.items {
		newVal, err := tracesImpl.processSingleMatchedSpanEventAttribute(ctx, se, entry)
		if err != nil {
			return err
		}

		m.Remove(entry.key)
		if newVal != nil {
			setInMap(m, entry.key, newVal)
		}
	}

	return nil
}

func (tracesImpl *tracesToTracesImpl) processSingleMatchedSpanAttribute(
	ctx context.Context,
	s *spanReference,
    m *matchedAttribute) (*foreignAttrRef, error) {
	if (!tracesImpl.shouldSampleSpanAttribute(s, m)) {
		return nil, nil
	}

	destinationUri, destinationUriErr := tracesImpl.computeDestinationUriForSpan(ctx, s, m)
	if destinationUriErr != nil {
		tracesImpl.settings.Logger.Error(
			"Could not create destination URI for span attribute",
			zap.String("attributeKey", m.key),
			zap.String("configRuleName", m.rule.Name),
		    zap.NamedError("error", destinationUriErr))
		return nil, destinationUriErr
	}

	b, berr := tracesImpl.backendRegistry.GetBackendForURI(destinationUri)
	if berr != nil {
		tracesImpl.settings.Logger.Error(
			"Could not find suitable storage backend for destination URI",
			zap.String("destinationUri", destinationUri),
		    zap.NamedError("error", berr))
		return nil, berr
	}

	d, derr := computeDataEncoding(m.value)
	if derr != nil {
		return nil, derr
	}

	contentType, contentTypeErr := tracesImpl.computeContentTypeForSpanAttribute(ctx, s, m, destinationUri, d)
	if contentTypeErr != nil {
		return nil, contentTypeErr
	}

	pending := &pendingUpload{
		storageBackend: b,
		key: m.key,
		data: d,
		destinationUri: destinationUri,
		contentType: contentType,
	}

	err := tracesImpl.scheduleUpload(ctx, pending)
	if err != nil {
		return nil, err
	}

	return tracesImpl.createForeignAttr(destinationUri, contentType), nil
}

func (tracesImpl *tracesToTracesImpl) consumeSpanContent(ctx context.Context, s *spanReference) error {
	m := s.span.Attributes()
	toProcess := newMatchedAttributeList()
	m.Range(func(k string, v pcommon.Value) bool { 
		rule := tracesImpl.spanAttributes.get(k)
		if rule == nil {
			return true
		}

		matchedAttr := &matchedAttribute{
			key: k,
			value: v,
			rule: rule,
		}

		toProcess.add(matchedAttr)
		tracesImpl.settings.Logger.Debug("Found matching span attribute", zap.String("attributeKey", k))
		return true
	})

	for _, entry := range toProcess.items {
		newVal, err := tracesImpl.processSingleMatchedSpanAttribute(ctx, s, entry)
		if err != nil {
			return err
		}

		m.Remove(entry.key)
		if newVal != nil {
			setInMap(m, entry.key, newVal)
		}
	}

	return nil
}

func (tracesImpl *tracesToTracesImpl) consumeSpan(ctx context.Context, s *spanReference) error {
	for i := 0; i < s.span.Events().Len(); i++ {
		event := s.span.Events().At(i)
		tracesImpl.settings.Logger.Debug(
			"Processing span event",
			zap.String("traceID", s.span.TraceID().String()),
			zap.String("spanID", s.span.SpanID().String()),
			zap.Int("eventIndex", i),
		    zap.String("eventName", event.Name()))
		ottlCtx := ottlspanevent.NewTransformContext(
			event,
			s.span,
			s.scope,
			s.resource,
			s.scopeSpans,
			s.resourceSpans)
		ref := &spanEventReference{
			span:    s,
			index:   i,
			event:   event,
			ottlCtx: ottlCtx,
		}
		if err := tracesImpl.consumeSpanEvent(ctx, ref); err != nil {
			return err
		}
	}
	return tracesImpl.consumeSpanContent(ctx, s)
}

func (tracesImpl *tracesToTracesImpl) Capabilities() consumer.Capabilities {
    return consumer.Capabilities{MutatesData: true}
}

func (tracesImpl *tracesToTracesImpl) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	tracesImpl.settings.Logger.Debug("Received new traces batch to process")

	resourceSpans := td.ResourceSpans()
	for i := 0; i < resourceSpans.Len(); i++ {
		resourceSpan := resourceSpans.At(i)
		resource := resourceSpan.Resource()
		scopeSpans := resourceSpan.ScopeSpans()
		for j := 0; j < scopeSpans.Len(); j++ {
			scopeSpan := scopeSpans.At(j)
			scope := scopeSpan.Scope()
			for k := 0; k < scopeSpan.Spans().Len(); k++ {
				span := scopeSpan.Spans().At(k)
				tracesImpl.settings.Logger.Debug(
					"Processing span",
					zap.Int("resouceIndex", i),
					zap.Int("scopeIndex", j),
					zap.Int("spanIndex", k),
					zap.String("traceID", span.TraceID().String()),
				    zap.String("spanID", span.SpanID().String()))
				ottlCtx := ottlspan.NewTransformContext(
					span, scope, resource, scopeSpan, resourceSpan)
				ref := &spanReference{
					resource:      resource,
					scope:         scope,
					span:          span,
					scopeSpans:    scopeSpan,
					resourceSpans: resourceSpan,
					ottlCtx:       ottlCtx,
				}
				if err := tracesImpl.consumeSpan(ctx, ref); err != nil {
					return err
				}
			}
		}
	}

	tracesImpl.settings.Logger.Debug("Forwarding processed batch to downstream consumer")
	return tracesImpl.nextConsumer.ConsumeTraces(ctx, td)
}

func spanAttributesFromConfig(cfg *Config) (*attributeRuleMap, error) {
	result := newAttributeRuleMap()

	tracesCfg := cfg.Traces
	if tracesCfg == nil {
		return result, nil
	}

	attributeCfg := tracesCfg.AttributeConfig
	if attributeCfg == nil {
		return result, nil
	}

	for _, rule := range attributeCfg.Rule {
		matchCfg := rule.Match
		if matchCfg == nil {
			return nil, fmt.Errorf("missing 'match' in rule %v", rule.Name)
		}

		locations := matchCfg.Locations
		if len(locations) == 0 {
			return nil, fmt.Errorf("missing 'locations' in rule %v", rule.Name)
		}

		for _, location := range locations {
			if location != "span" {
				return nil, fmt.Errorf(
					"in rule %v: unsupported location: %v; only 'span' supported for now", rule.Name, location)
			}
		}

		err := result.add(rule)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func spanEventAttributesFromConfig(cfg *Config) (*eventAttributeRules, error) {
	result := newEventAttributeRules()

	tracesCfg := cfg.Traces
	if tracesCfg == nil {
		return result, nil
	}

	eventsCfg := tracesCfg.SpanEventsConfig
	if eventsCfg == nil {
		return result, nil	
	}

	for _, group := range eventsCfg.Groups {
		err := result.add(group)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func createSpanFuncs() map[string]ottl.Factory[ottlspan.TransformContext] {
	// TODO: refactor function construction out of "transformprocessor/internal" so
	// so that a common set of functions can be used here, as well.
	return ottlfuncs.StandardFuncs[ottlspan.TransformContext]()
}

func createSpanEventFuncs() map[string]ottl.Factory[ottlspanevent.TransformContext] {
	// TODO: refactor function construction out of "transformprocessor/internal" so
	// so that a common set of functions can be used here, as well.
	return ottlfuncs.StandardFuncs[ottlspanevent.TransformContext]()
}

func createTracesToTracesConnector(
	ctx context.Context,
	settings connector.Settings,
	config component.Config,
	nextConsumer consumer.Traces) (connector.Traces, error) {
  cfg := config.(*Config)
  if cfg.Traces == nil {
	  settings.Logger.Info("No trace configuration found; using pass-through connector.")
	  return &passThroughTracesConnector{
		  nextConsumer: nextConsumer,
	  }, nil
  }

  backendRegistry, backendRegistryErr := backend.NewRegistry()
  if backendRegistryErr != nil {
	  settings.Logger.Error(
		  "Failed to construct backend registry",
		  zap.NamedError("error", backendRegistryErr))
	  return nil, backendRegistryErr
  }
  settings.Logger.Debug("Constructed backend registry")

  spanAttributes, spanAttributesErr := spanAttributesFromConfig(cfg)
  if spanAttributesErr != nil {
	  settings.Logger.Error(
		  "Failed to gather span attribute configuration",
		  zap.NamedError("error", spanAttributesErr))
	  return nil, spanAttributesErr
  }
  settings.Logger.Debug("Collected span attribute configuration")

  spanEvents, spanEventsErr := spanEventAttributesFromConfig(cfg)
  if spanEventsErr != nil {
	settings.Logger.Error(
		"Failed to gather span event attribute configuration",
		zap.NamedError("error", spanEventsErr))
	  return nil, spanEventsErr
  }
  settings.Logger.Debug("Collected span event attribute configuration")


  result := &tracesToTracesImpl{
	  settings: settings,
	  nextConsumer: nextConsumer,
	  spanAttributes: spanAttributes,
	  spanEvents: spanEvents,
	  backendRegistry: backendRegistry,
	  spanFuncs: createSpanFuncs(),
	  spanEventFuncs: createSpanEventFuncs(),
	  seed: maphash.MakeSeed(),
  }
  settings.Logger.Debug("Constructed traces-to-traces connector")

  return result, nil
}
