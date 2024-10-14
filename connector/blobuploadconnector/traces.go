// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "blobuploadconnector" provides a connector that writes
// certain specified attributes to a blob storage backend.
//
// The file "traces.go" file provides the logic for the traces signal type.
package blobuploadconnector

import (
	"errors"
	"fmt"
	"strings"
	"time"
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

	"github.com/open-telemetry/opentelemetry-collector-contrib/connector/blobuploadconnector/internal/backend"
	"github.com/open-telemetry/opentelemetry-collector-contrib/connector/blobuploadconnector/internal/contenttype"
	"github.com/open-telemetry/opentelemetry-collector-contrib/connector/blobuploadconnector/internal/foreignattr"
	"github.com/open-telemetry/opentelemetry-collector-contrib/connector/blobuploadconnector/internal/payload"
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
	if acr == nil {
		return errors.New("Must supply a non-nil AttributeConfigRule")
	}
	if acr.Match == nil {
		return fmt.Errorf("Attribute config rule %v is missing a required 'match' configuration.", acr.Name)
	}
	if acr.Match.Key == "" {
		return fmt.Errorf("The match spec in attribute config rule %v is missing a non-empty 'key'.", acr.Name)
	}
	if arm.attributeNameToRule == nil {
		arm.attributeNameToRule = make(map[string]*AttributeConfigRule)
	}
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
				mapsToUpdate = append(mapsToUpdate, newMap)
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
	uploadDurationNanos time.Duration
	running bool
	pendingUploadChannel chan *pendingUpload
	shutDownCompleted chan bool
}

type uploadMetadataImpl struct {
	contentType string
	labels map[string]string
}

func (u *uploadMetadataImpl) ContentType() string {
	return u.contentType
}

func (u *uploadMetadataImpl) Labels() map[string]string {
	return u.labels
}

func (tracesImpl *tracesToTracesImpl) uploadInBackground() {
	tracesImpl.settings.Logger.Debug("[uploadInBackground] Background uploader thread now running.")
	var cleanupFuncs = make([]func(), 0)
	for p := range tracesImpl.pendingUploadChannel {
		tracesImpl.settings.Logger.Debug(
			"[uploadInBackground] Received pending upload",
			zap.String("key", p.key),
			zap.Int("dataSizeBytes", len(p.data)),
			zap.String("destinationURI", p.destinationURI))
		metadata := &uploadMetadataImpl{
			contentType: p.contentType,
			labels: p.metadataLabels,
		}
		ctx, cancel := context.WithTimeout(context.Background(), tracesImpl.uploadDurationNanos)
		cleanupFuncs = append(cleanupFuncs, cancel)


		tracesImpl.settings.Logger.Debug(
			"[uploadInBackground] Starting pending upload",
			zap.String("key", p.key),
			zap.Int("dataSizeBytes", len(p.data)),
			zap.String("destinationURI", p.destinationURI))
		err := p.storageBackend.Upload(ctx, p.destinationURI, p.data, metadata)
		if err != nil {
			tracesImpl.settings.Logger.Error(
				"[uploadInBackground] Failed to upload in background",
				zap.String("key", p.key),
				zap.String("destinationURI", p.destinationURI),
				zap.Int("dataSizeBytes", len(p.data)),
				zap.Duration("timeout", tracesImpl.uploadDurationNanos),
				zap.String("contentType", p.contentType),
				zap.NamedError("backendError", err),
			)
		} else {
			tracesImpl.settings.Logger.Debug(
				"[uploadInBackground] Completed upload",
				zap.String("key", p.key),
				zap.String("destinationURI", p.destinationURI),
				zap.Int("dataSizeBytes", len(p.data)),
				zap.Duration("timeout", tracesImpl.uploadDurationNanos),
				zap.String("contentType", p.contentType),
			)
		}
	}

	for _, cleanup := range cleanupFuncs {
		cleanup()
	}

	tracesImpl.shutDownCompleted <- true
	close(tracesImpl.shutDownCompleted)
}

func (tracesImpl *tracesToTracesImpl) Start(ctx context.Context, host component.Host) error {
	tracesImpl.settings.Logger.Debug("Starting connector...")
	go tracesImpl.uploadInBackground()
	tracesImpl.running = true
	tracesImpl.settings.Logger.Debug("Connector now running.")
	return nil
}

func (tracesImpl *tracesToTracesImpl) Shutdown(ctx context.Context) error {
	tracesImpl.settings.Logger.Debug("Shutting down the connector...")
	tracesImpl.running = false
	close(tracesImpl.pendingUploadChannel)
	for shutDownCompleted := range tracesImpl.shutDownCompleted {
		if shutDownCompleted {
			tracesImpl.settings.Logger.Debug("Connector shut down successfully")
			return nil
		}
	}
	tracesImpl.settings.Logger.Warn("Unexpected failure while shutting down the connector.")
	return errors.New("Failed to shut down the connector.")
}

func (tracesImpl *tracesToTracesImpl) shouldSampleAttributeInTrace(m *matchedAttribute, traceID pcommon.TraceID) bool {
	if m.rule.Action == nil  {
		tracesImpl.settings.Logger.Debug(
			"[shouldSampleAttributeInTrace] should sample: false -- no action.",
			zap.String("key", m.key),
		    zap.String("rule", m.rule.Name))
		return false
	}
	if m.rule.Action.Sampling == nil {
		tracesImpl.settings.Logger.Debug(
			"[shouldSampleAttributeInTrace] should sample: true -- no sample config.",
			zap.String("key", m.key),
		    zap.String("rule", m.rule.Name))
		return true
	}
	if !m.rule.Action.Sampling.Enabled {
		tracesImpl.settings.Logger.Debug(
			"[shouldSampleAttributeInTrace] should sample: true -- sampling disabled.",
			zap.String("key", m.key),
			zap.String("rule", m.rule.Name))
		return true
	}

	samplePercent := m.rule.Action.Sampling.Percent
	hashVal := maphash.Bytes(tracesImpl.seed, []byte(traceID[:]))
	mod100 := int(hashVal % 100)
	result := mod100 < samplePercent
	tracesImpl.settings.Logger.Debug(
		"[shouldSampleAttributeInTrace] sampling decision made",
		zap.String("key", m.key),
		zap.String("rule", m.rule.Name),
		zap.Bool("shouldSample", result),
		zap.Int("samplePercent", samplePercent),
		zap.Int("randomHashMod100", mod100))
	return result
}

func (tracesImpl *tracesToTracesImpl) shouldSampleSpanEventAttribute(se *spanEventReference, m *matchedAttribute) bool {
	return tracesImpl.shouldSampleAttributeInTrace(m, se.traceID()) 
}

func (tracesImpl *tracesToTracesImpl) shouldSampleSpanAttribute(s *spanReference, m *matchedAttribute) bool {
	return tracesImpl.shouldSampleAttributeInTrace(m, s.traceID()) 
}

func (tracesImpl *tracesToTracesImpl) getTelemetrySettings() component.TelemetrySettings {
	return tracesImpl.settings.TelemetrySettings
}

func (tracesImpl *tracesToTracesImpl) interpolateSpanEventWithOttl(
	ctx context.Context,
	pattern string,
	se *spanEventReference) (string, error) {
  parser, err := ottlspanevent.NewParser(tracesImpl.spanEventFuncs, tracesImpl.getTelemetrySettings())
 if err != nil {
	return "", err
 }

 return parser.InterpolateString(ctx, pattern, se.ottlCtx)
}

func (tracesImpl *tracesToTracesImpl) interpolateSpanEvent(
	ctx context.Context,
	pattern string,
	se *spanEventReference) (string, error) {
  // TODO: eliminate this rewriting when OTTL context for span event supports all of the required fields.
  updatedPattern := strings.ReplaceAll(pattern, "${event_index}", fmt.Sprintf("%v", se.index))
  return tracesImpl.interpolateSpanEventWithOttl(ctx, updatedPattern, se)
}

func (tracesImpl *tracesToTracesImpl) interpolateSpan(
	ctx context.Context,
	pattern string,
	s *spanReference) (string, error) {
  parser, err := ottlspan.NewParser(tracesImpl.spanFuncs, tracesImpl.getTelemetrySettings())
  if err != nil {
	  return "", err
  }

  return parser.InterpolateString(ctx, pattern, s.ottlCtx)
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
	return payload.ValueToBytes(value)
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
    ((contentTypeCfg.Automatic != nil) && (contentTypeCfg.Automatic.Enabled)) {
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
	destinationURI string
	contentType string
	metadataLabels map[string]string
}

func (tracesImpl *tracesToTracesImpl) scheduleUpload(
	ctx context.Context,
	pending *pendingUpload) error {
  if !tracesImpl.running {
	  return errors.New("Cannot upload further to the channel; shutting down.")
  }
  tracesImpl.settings.Logger.Debug(
	  "[scheduleUpload] Queing pending upload.",
	  zap.String("key", pending.key),
	  zap.Int("dataSizeBytes", len(pending.data)),
	  zap.String("destinationURI", pending.destinationURI))
  tracesImpl.pendingUploadChannel <- pending
  return nil
}

func (tracesImpl *tracesToTracesImpl) processSingleMatchedSpanEventAttribute(
	ctx context.Context,
	se *spanEventReference,
    m *matchedAttribute) (foreignattr.ForeignAttrRef, error) {
	if (!tracesImpl.shouldSampleSpanEventAttribute(se, m)) {
		return nil, nil
	}

	destinationURI, destinationURIErr := tracesImpl.computeDestinationUriForSpanEvent(ctx, se, m)
	if destinationURIErr != nil {
		tracesImpl.settings.Logger.Error(
			"Could not create destination URI for span event attribute",
			zap.String("attributeKey", m.key),
			zap.String("configRuleName", m.rule.Name),
		    zap.NamedError("error", destinationURIErr))
		return nil, destinationURIErr
	}

	b, berr := tracesImpl.backendRegistry.GetBackendForURI(destinationURI)
	if berr != nil {
		tracesImpl.settings.Logger.Error(
			"Could not find suitable storage backend for destination URI",
			zap.String("destinationURI", destinationURI),
		    zap.NamedError("error", berr))
		return nil, berr
	}

	d, derr := computeDataEncoding(m.value)
	if derr != nil {
		return nil, derr
	}

	contentType, contentTypeErr := tracesImpl.computeContentTypeForSpanEventAttribute(ctx, se, m, destinationURI, d)
	if contentTypeErr != nil {
		return nil, contentTypeErr
	}

	pending := &pendingUpload{
		storageBackend: b,
		key: m.key,
		data: d,
		destinationURI: destinationURI,
		contentType: contentType,
	}

	err := tracesImpl.scheduleUpload(ctx, pending)
	if err != nil {
		return nil, err
	}

	return foreignattr.FromURIWithContentType(destinationURI, contentType), nil
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
			newVal.SetInMap(entry.key, m)
		}
	}

	return nil
}

func (tracesImpl *tracesToTracesImpl) processSingleMatchedSpanAttribute(
	ctx context.Context,
	s *spanReference,
    m *matchedAttribute) (foreignattr.ForeignAttrRef, error) {
	if (!tracesImpl.shouldSampleSpanAttribute(s, m)) {
		return nil, nil
	}

	destinationURI, destinationURIErr := tracesImpl.computeDestinationUriForSpan(ctx, s, m)
	if destinationURIErr != nil {
		tracesImpl.settings.Logger.Error(
			"Could not create destination URI for span attribute",
			zap.String("attributeKey", m.key),
			zap.String("configRuleName", m.rule.Name),
		    zap.NamedError("error", destinationURIErr))
		return nil, destinationURIErr
	}

	b, berr := tracesImpl.backendRegistry.GetBackendForURI(destinationURI)
	if berr != nil {
		tracesImpl.settings.Logger.Error(
			"Could not find suitable storage backend for destination URI",
			zap.String("destinationURI", destinationURI),
		    zap.NamedError("error", berr))
		return nil, berr
	}

	d, derr := computeDataEncoding(m.value)
	if derr != nil {
		return nil, derr
	}

	contentType, contentTypeErr := tracesImpl.computeContentTypeForSpanAttribute(ctx, s, m, destinationURI, d)
	if contentTypeErr != nil {
		return nil, contentTypeErr
	}

	pending := &pendingUpload{
		storageBackend: b,
		key: m.key,
		data: d,
		destinationURI: destinationURI,
		contentType: contentType,
	}

	err := tracesImpl.scheduleUpload(ctx, pending)
	if err != nil {
		return nil, err
	}

	return foreignattr.FromURIWithContentType(destinationURI, contentType), nil
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
			newVal.SetInMap(entry.key, m)
		}
	}

	return nil
}

func (tracesImpl *tracesToTracesImpl) consumeSpan(ctx context.Context, s *spanReference) error {
	tracesImpl.settings.Logger.Debug(
		"[consumeSpan] Processing span",
		zap.String("traceID", s.span.TraceID().String()),
		zap.String("spanID", s.span.SpanID().String()))
	updatedEvents := ptrace.NewSpanEventSlice()
	updatedEvents.EnsureCapacity(s.span.Events().Len())
	for i := 0; i < s.span.Events().Len(); i++ {
		event := s.span.Events().At(i)
		tracesImpl.settings.Logger.Debug(
			"[consumeSpan] Processing span event",
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
		ref.event.MoveTo(updatedEvents.AppendEmpty())
	}
	updatedEvents.CopyTo(s.span.Events())
	return tracesImpl.consumeSpanContent(ctx, s)
}

func (tracesImpl *tracesToTracesImpl) Capabilities() consumer.Capabilities {
    return consumer.Capabilities{MutatesData: true}
}

func (tracesImpl *tracesToTracesImpl) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	tracesImpl.settings.Logger.Debug("Received new traces batch to process")

	if !tracesImpl.running {
		tracesImpl.settings.Logger.Error(
			"Connector has been shut down or hasn't started yet, but received new traces.")
		return errors.New(
			"Connector not running; did you already Shutdown()? Or have you forgotten to Start() the connector before sending data to it?")
	}

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
					"[ConsumeTraces] Processing span",
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

	tracesImpl.settings.Logger.Debug("[ConsumeTraces] Forwarding processed batch to downstream consumer")
	return tracesImpl.nextConsumer.ConsumeTraces(ctx, td)
}

func spanAttributesFromConfig(logger *zap.Logger, cfg *Config) (*attributeRuleMap, error) {
	result := newAttributeRuleMap()

	tracesCfg := cfg.Traces
	if tracesCfg == nil {
		logger.Debug("[spanAttributesConfig] No traces config found.")
		return result, nil
	}

	attributeCfg := tracesCfg.AttributeConfig
	if attributeCfg == nil {
		logger.Debug("[spanAttributesConfig] 'traces' config missing 'attributes' config.")
		return result, nil
	}

	for _, rule := range attributeCfg.Rule {
		logger.Debug("[spanAttributesConfig] Processing span attributes config rule",
	                 zap.String("ruleName", rule.Name))
		matchCfg := rule.Match
		if matchCfg == nil {
			logger.Debug(
				"[spanAttributeConfig] Missing 'match' stanza in rule",
			    zap.String("ruleName", rule.Name))
			return nil, fmt.Errorf("missing 'match' in rule %v", rule.Name)
		}

		locations := matchCfg.Locations
		for _, location := range locations {
			if location != "span" {
				logger.Debug(
					"[spanAttributeConfig] Unsupported 'locations' entry in rule",
					zap.String("ruleName", rule.Name),
				    zap.String("location", location))
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

func spanEventAttributesFromConfig(logger *zap.Logger, cfg *Config) (*eventAttributeRules, error) {
	result := newEventAttributeRules()

	tracesCfg := cfg.Traces
	if tracesCfg == nil {
		logger.Debug("[spanEventAttributesFromConfig] No 'traces' config found.")
		return result, nil
	}

	eventsCfg := tracesCfg.SpanEventsConfig
	if eventsCfg == nil {
		logger.Debug("[spanEventAttributesFromConfig] No 'events' config in the 'traces' config.")
		return result, nil	
	}

	for _, group := range eventsCfg.Groups {
		logger.Debug(
			"[spanEventAttributesFromConfig] Found span event group",
			zap.String("groupName", group.Name))
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

// Indirection around construction of the backend registry, used to
// replace the registry with a mock implementation in tests.
type backendRegistryFactory interface {
	createRegistry() (backend.Registry, error)
}

// Default backend registry implementation that uses the real backends.
type defaultBackendRegistryFactory struct {}
func (d *defaultBackendRegistryFactory) createRegistry() (backend.Registry, error) {
	return backend.NewRegistry()
}


// Core implementation that accepts an alternative backend factory, thereby
// allowing for the backends to be replaced in the test code.
func createTracesToTracesConnectorWithRegistryFactory(
	ctx context.Context,
	settings connector.Settings,
	config component.Config,
	nextConsumer consumer.Traces,
	registryFactory backendRegistryFactory) (connector.Traces, error) {
  cfg := config.(*Config)
  validationErr := cfg.Validate()
  if validationErr != nil {
	  return nil, validationErr
  }
  settings.Logger.Debug(
	  "Creating traces-to-traces blobattributeuploaderconnector.",
	  zap.Any("config", config))
  if cfg.Traces == nil {
	  settings.Logger.Info("No trace configuration found; using pass-through connector.")
	  return &passThroughTracesConnector{
		  nextConsumer: nextConsumer,
	  }, nil
  }

  backendRegistry, backendRegistryErr := registryFactory.createRegistry()
  if backendRegistryErr != nil {
	  settings.Logger.Error(
		  "Failed to construct backend registry",
		  zap.NamedError("error", backendRegistryErr))
	  return nil, backendRegistryErr
  }
  settings.Logger.Debug("Constructed backend registry")

  spanAttributes, spanAttributesErr := spanAttributesFromConfig(settings.Logger, cfg)
  if spanAttributesErr != nil {
	  settings.Logger.Error(
		  "Failed to gather span attribute configuration",
		  zap.NamedError("error", spanAttributesErr))
	  return nil, spanAttributesErr
  }
  settings.Logger.Debug(
	  "Collected span attribute configuration",
      zap.Any("spanAttributes", spanAttributes))

  spanEvents, spanEventsErr := spanEventAttributesFromConfig(settings.Logger, cfg)
  if spanEventsErr != nil {
	settings.Logger.Error(
		"Failed to gather span event attribute configuration",
		zap.NamedError("error", spanEventsErr))
	  return nil, spanEventsErr
  }
  settings.Logger.Debug(
	  "Collected span event attribute configuration",
	  zap.Any("spanEvents", spanEvents))

  result := &tracesToTracesImpl{
	  settings: settings,
	  nextConsumer: nextConsumer,
	  spanAttributes: spanAttributes,
	  spanEvents: spanEvents,
	  backendRegistry: backendRegistry,
	  spanFuncs: createSpanFuncs(),
	  spanEventFuncs: createSpanEventFuncs(),
	  seed: maphash.MakeSeed(),
	  uploadDurationNanos: time.Duration(cfg.UploadTimeoutNanos),
	  running: false,
	  pendingUploadChannel: make(chan *pendingUpload, cfg.UploadQueueSize),
	  shutDownCompleted: make(chan bool, 1),
  }
  settings.Logger.Debug("Constructed traces-to-traces connector")

  return result, nil
}


// Called by the real implementation code in "factory.go".
func createTracesToTracesConnector(
	ctx context.Context,
	settings connector.Settings,
	config component.Config,
	nextConsumer consumer.Traces) (connector.Traces, error) {
  registryFactory := &defaultBackendRegistryFactory{}
  return createTracesToTracesConnectorWithRegistryFactory(
	  ctx, settings, config, nextConsumer, registryFactory)
}