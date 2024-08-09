// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "blobattributeuploadconnector" provides a connector that writes
// certain specified attributes to a blob storage backend.
//
// The file "traces.go" file provides the logic for the traces signal type.
package blobattributeuploadconnector

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/connector"
	"go.opentelemetry.io/collector/consumer"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/contexts/ottlspan"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/contexts/ottlspanevent"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/ottlfuncs"
)

type passThroughTracesConnector {
	nextConsumer consumer.Traces
	component.StartFunc
	component.ShutdownFunc
}

func (c *passThroughTracesConnector) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	return nextConsumer.ConsumeTraces(ctx, td)
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

type spanEventReference struct {
	span    *spanReference
	index   int
	event   ptrace.SpanEvent
	ottlCtx ottlspanevent.TransformContext
}

type attributeRuleMap struct {
	attributeNameToRule map[string]*AttributeConfigRule
}

func newAttributeRuleMap() *attributeRuleMap {
	return &attributeRuleMap{
		attributeNameToRule: make(map[string]*AttributeConfigRule)
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

	var mapsToUpdate = make([]*attributeRuleMap)
	if secg.EventName == nil || secg.EventName.MatchAll {
		mapsToUpdate = append(mapsToUpdate, ear.allEvents) 
	} else {
		for _, name := range ear.EventName.MatchIfAnyEqualTo {
			existing, present := ear.eventNameToRuleMap[name]
			if present {
				mapsToUpdate = append(mapsToUpdate, existing)
			} else {
				newMap = newAttributeRuleMap()
				ear.eventNameToRuleMap[name] = newMap
				mapsToUpdate = append(mapsToUpdate, existing)
			}
		}
	}

	for _, rule := range secg.Attributes.Rule {
		for _, m := mapsToUpdate {
			if err := m.add(rule) ; err != nil {
				return err
			}
		}
	}

	return nil
}

type applicableEventAttributeRules {
	values []*attributeRuleMap
}

func (ear *eventAttributeRules) get(eventName string) *applicableEventAttributeRules {
	existing, present := ear.eventNameToRuleMap[eventName]
	if present {
		return &applicableEventAttributeRules{
			values: []*attributeRuleMap{
				existing,
				ear.allEvents
			}
		}
	}

	return &applicableEventAttributeRules{
		values: []*attributeRuleMap{ear.allEvents}
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
		items: make([]*matchedAttribute)
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
	component.StartFunc
	component.ShutdownFunc
}

func (tracesImpl *tracesToTracesImpl) consumeSpanEvent(ctx context.Context, se *spanEventReference) error {
	// TODO: ...
	return nil
}

func (tracesImpl *tracesToTracesImpl) processSingleMatchedSpanAttribute(
	ctx context.Context,
	s *spanReference,
    m *matchedAttribute) (pcommon.Value, error) {
	// TODO: ...
	return nil, nil
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
		return true
	})

	for _, entry := toProcess.items {
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
				ottlCtx := ottlspan.NewTransformContext(
					span, scope, resource, scopeSpans, resourceSpans)
				ref := &spanReference{
					resource:      resource,
					scope:         scope,
					span:          span,
					scopeSpans:    scopeSpans,
					resourceSpans: resourceSpans,
					ottlCtx:       ottlCtx,
				}
				if err := tracesImpl.consumeSpan(ctx, ref); err != nil {
					return err
				}
			}
		}
	}

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
	  return &passThroughTracesConnector{
		  nextConsumer: nextConsumer,
	  }, nil
  }

  backendRegistry, backendRegistryErr := backend.NewRegistry()
  if backendRegistryErr != nil {
	  return nil, backendRegistryErr
  }

  spanAttributes, spanAttributesErr := spanAttributesFromConfig(cfg)
  if spanAttributesErr != nil {
	  return nil, spanAttributesErr
  }

  spanEvents, spanEventsErr := spanEventAttributesFromConfig(cfg)
  if spanEventsErr != nil {
	  return nil, spanEventsErr
  }

  result := &tracesToTracesImpl{
	  settings: settings,
	  nextConsumer: settings,
	  spanAttributes: spanAttributes,
	  spanEvents: spanEvents,
	  backendRegistry: backendRegistry,
	  spanFuncs: createSpanFuncs(),
	  spanEventFuncs: createSpanEventFuncs(),
  }
}
