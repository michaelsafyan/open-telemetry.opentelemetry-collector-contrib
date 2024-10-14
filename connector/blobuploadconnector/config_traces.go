// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "blobuploadconnector" provides a connector that writes
// certain specified attributes/fields to a blob storage backend.
//
// The file "config_traces.go" manages the subset of config options
// that relate to the traces signal type.
package blobuploadconnector

import (
	"errors"
	"fmt"
)

// "TracesConfig" defines how this exporter should handle the traces signal.
type TracesConfig struct {
	// Configuration regarding the handling of trace attributes.
	AttributeConfig *TraceAttributeConfig `mapstructure:"attributes"`

	// Configuration regarding the handling of span events.
	SpanEventsConfig *SpanEventsConfig `mapstructure:"events"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// "TraceAttributeConfig" governs the handling of attribute information in
// trace telemetry data (as oppposed to event attributes).
type TraceAttributeConfig struct {
	// Individual entries, each applying to a different key to match.
	Rule []*AttributeConfigRule `mapstructure:"rules"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Configuration that is intended to apply to span events.
type SpanEventsConfig struct {
	// Groups of rules, grouped by event name.
	Groups []*SpanEventsConfigGroup `mapstructure:"groups"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Configuration that applies to a list of named events.
type SpanEventsConfigGroup struct {
	// Name used to identify the group in the configuration
	Name string `mapstructure:"name"`

	// Describes how to to match the event name
	EventName *EventNameMatchConfig `mapstructure:"event_name"`

	// Rules / configuration that apply to attributes in the group
	Attributes *SpanEventAttributeConfig `mapstructure:"attributes"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Configures how to match a particular event name
type EventNameMatchConfig struct {
	// Indicates that all event names should be matched.
	MatchAll bool `mapstructure:"match_all"`

	// A list of exact names to match.
	MatchIfAnyEqualTo []string `mapstructure:"match_if_any_equal_to"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Configures how to process the attributes of the span events
type SpanEventAttributeConfig struct {
	// Individual entries, each applying to a different key to match.
	Rule []*AttributeConfigRule `mapstructure:"rules"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Validate verifies that the configuration is well-formed.
func (tc *TracesConfig) Validate() error {
	if tc.AttributeConfig != nil {
		if err := tc.AttributeConfig.Validate(); err != nil {
			return err
		}
	}
	if tc.SpanEventsConfig != nil {
		if err := tc.SpanEventsConfig.Validate(); err != nil {
			return err
		}
	}
	if err := errorIfUnknown(tc.UnknownFields); err != nil {
		return err
	}
	return nil
}

func validateTraceLocation(ruleName string, location string) error {
	if location == "span" {
		return nil
	}
	if location == "scope" || location == "instrumentationScope" || location == "instrumentation_scope" {
		return nil
	}
	if location == "resource" {
		return nil
	}
	return fmt.Errorf("In rule %v: unknown location: %v. Valid values are: [span, scope, resource].", ruleName, location)
}

// Validate verifies that the configuration is well-formed.
func (tac *TraceAttributeConfig) Validate() error {
	names := make(map[string]bool)
	for _, rule := range tac.Rule {
		if err := rule.Validate(); err != nil {
			return err
		}
		if _, found := names[rule.Name]; found {
			return fmt.Errorf("Rule name %v found more than once.", rule.Name)
		}
		names[rule.Name] = true
		for _, location := range rule.Match.Locations {
			if err := validateTraceLocation(rule.Name, location); err != nil {
				return err
			}
		}
	}
	if err := errorIfUnknown(tac.UnknownFields); err != nil {
		return err
	}
	return nil
}

// Validate verifies that the configuration is well-formed.
func (sec *SpanEventsConfig) Validate() error {
	for _, group := range sec.Groups {
		if err := group.Validate(); err != nil {
			return err
		}
	}
	if err := errorIfUnknown(sec.UnknownFields); err != nil {
		return err
	}
	return nil
}

// Validate verifies that the configuration is well-formed.
func (secg *SpanEventsConfigGroup) Validate() error {
	if secg.Name == "" {
		return errors.New("Event group missing name")
	}
	if secg.EventName != nil {
		if err := secg.EventName.Validate(); err != nil {
			return err
		}
	}
	if secg.Attributes != nil {
		if err := secg.Attributes.Validate(); err != nil {
			return err
		}
	}
	if err := errorIfUnknown(secg.UnknownFields); err != nil {
		return err
	}
	return nil
}

// Validate verifies that the configuration is well-formed.
func (enmc *EventNameMatchConfig) Validate() error {
	if enmc.MatchAll && len(enmc.MatchIfAnyEqualTo) > 0 {
		return errors.New("Cannot set both 'match_all' and 'match_if_any_equal_to'.")
	}
	if !enmc.MatchAll && (len(enmc.MatchIfAnyEqualTo) == 0) {
		return errors.New("Never matches any event; set 'match_all' or 'match_if_any_equal_to'.")
	}
	return nil
}

// Validate verifies that the configuration is well-formed.
func (seac *SpanEventAttributeConfig) Validate() error {
	for _, rule := range seac.Rule {
		if err := rule.Validate(); err != nil {
			return err
		}
		if len(rule.Match.Locations) > 0 {
			return errors.New("Cannot set match location for span events.")
		}
	}
	if err := errorIfUnknown(seac.UnknownFields); err != nil {
		return err
	}
	return nil
}
