// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "blobattributeuploadconnector" provides a connector that writes
// certain specified attributes to a blob storage backend.
//
// The file "config.go" manages interaction with config options.
package blobuploadconnector

import (
	"errors"
	"fmt"
)

// "Config" defines the configuration structure for this connector.
type Config struct {
	// The maximum number of files/blobs to enqueue for upload. Note
	// that this is a count of the number of items/files, not a count
	// of the total bytes or throughput amount.
	UploadQueueSize int64 `mapstructure:"upload_queue_size"`

	// Maximum duration to allow for an upload to a storage backend.
	UploadTimeoutNanos int64 `mapstructure:"upload_timeout_nanos"`

	// Configuration regarding how this should apply to the traces signal.
	Traces *TracesConfig `mapstructure:"traces"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

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

// "AttributeConfigRule" defines the handling of a single attribute.
type AttributeConfigRule struct {
	// Identifies the rule that is being handled.
	Name string `mapstructure:"name"`

	// Determines which attribute should be matched by the rule.
	Match *MatchConfig `mapstructure:"match"`

	// Determines the kind of action to take for the matching attribute.
	Action *ActionConfig `mapstructure:"action"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// "MatchConfig" defines how to determine if an attribute should be processed.
type MatchConfig struct {
	// The name of the attribute that should be matched
	Key string `mapstructure:"key"`

	// If specified, match the specified key only in the
	// given locations (e.g. "span", "scope", "resource").
	Locations []string `mapstructure:"locations"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// "ActionConfig" defines the kind of action which should be taken.
type ActionConfig struct {
	// If only a subset of the matched keys should be handled.
	Sampling *SamplingConfig `mapstructure:"sample"`

	// How to upload the sampled content.
	Upload *UploadConfig `mapstructure:"upload"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// "SamplingConfig" defines how to handle sampling.
type SamplingConfig struct {
	// Whether downsampling is enabled.
	Enabled bool `mapstructure:"enabled"`

	// What percentage number ([0, 100]) to sample.
	Percent int `mapstructure:"percent"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Describes how to upload the content to the blob storage.
type UploadConfig struct {
	// Where to write the configuration.
	DestinationUri string `mapstructure:"destination_uri"`

	// What content type to use in the metadata.
	ContentType *ContentTypeConfig `mapstructure:"content_type"`

	// Additional metadata to attach to the uploaded content.
	MetadataLabels []*MetadataLabelConfig `mapstructure:"labels"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Configures how the content type will be determined.
type ContentTypeConfig struct {
	// Configures automatic content-type inference.
	Automatic *AutoContentTypeConfig `mapstructure:"automatic"`

	// Allows the content type to be specified from a static string.
	StaticValue string `mapstructure:"static_value"`

	// Allows the content type to be extracted from other properties.
	Extraction *ExtractionConfig `mapstructure:"extraction"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Configuration for automatic content type inference.
type AutoContentTypeConfig struct {
	// Whether to enable the automatic content type inference.
	Enabled bool `mapstructure:"enabled"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Configures how to extract some piece of information.
type ExtractionConfig struct {
	// The expression that is to be evaluated.
	Expression string `mapstructure:"expression"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Configures how to add a metadata label to the uploaded file.
type MetadataLabelConfig struct {
	// The key of the metadata property.
	Key string `mapstructure:"key"`

	// The value of the metadata property.
	Value *MetadataLabelValueConfig `mapstructure:"value"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Configures how to set the value of the property.
type MetadataLabelValueConfig struct {
	// Allows the label value to be specified from a static string.
	StaticValue string `mapstructure:"static_value"`

	// Allows the label value to be extracted from other properties.
	Extraction *ExtractionConfig `mapstructure:"extraction"`

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

// Helper to raise errors if there are any unknown fields
func errorIfUnknown(u map[string]interface{}) error {
	for k := range u {
		return fmt.Errorf("Found unknown key: %v", k)
	}
	return nil
}

// Validate verifies that the configuration is well-formed.
func (c *Config) Validate() error {
	if c.Traces != nil {
		if err := c.Traces.Validate(); err != nil {
			return err
		}
	}
	if err := errorIfUnknown(c.UnknownFields); err != nil {
		return err
	}
	return nil
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
func (acr *AttributeConfigRule) Validate() error {
	if len(acr.Name) == 0 {
		return errors.New("Missing required name for config rule.")
	}
	if acr.Match == nil {
		return errors.New("Must specify a 'match' condition.")
	}
	if err := acr.Match.Validate(); err != nil {
		return err
	}
	if acr.Action == nil {
		return errors.New("Must specifify an 'action' condition.")
	}
	if err := acr.Action.Validate(); err != nil {
		return err
	}
	if err := errorIfUnknown(acr.UnknownFields); err != nil {
		return err
	}
	return nil
}

// Validate verifies that the configuration is well-formed.
func (mc *MatchConfig) Validate() error {
	if len(mc.Key) == 0 {
		return errors.New("Missing required key in match configuration.")
	}
	if err := errorIfUnknown(mc.UnknownFields); err != nil {
		return err
	}
	return nil
}

// Validate verifies that the configuration is well-formed.
func (ac *ActionConfig) Validate() error {
	if ac.Sampling != nil {
		if err := ac.Sampling.Validate(); err != nil {
			return err
		}
	}
	if ac.Upload == nil {
		return errors.New("Must specify 'upload' in action.")
	}
	if err := ac.Upload.Validate(); err != nil {
		return err
	}
	if err := errorIfUnknown(ac.UnknownFields); err != nil {
		return err
	}
	return nil
}

// Validate verifies that the configuration is well-formed.
func (sc *SamplingConfig) Validate() error {
	if sc.Percent < 0 || sc.Percent > 100 {
		return fmt.Errorf("Invalid percentage: %v", sc.Percent)
	}
	if err := errorIfUnknown(sc.UnknownFields); err != nil {
		return err
	}
	return nil
}

// Validate verifies that the configuration is well-formed.
func (uc *UploadConfig) Validate() error {
	if len(uc.DestinationUri) == 0 {
		return errors.New("Destination URI must not be empty.")
	}
	if uc.ContentType != nil {
		if err := uc.ContentType.Validate(); err != nil {
			return err
		}
	}
	metadataKeys := make(map[string]bool)
	for _, metadata := range uc.MetadataLabels {
		if err := metadata.Validate(); err != nil {
			return err
		}
		if _, found := metadataKeys[metadata.Key]; found {
			return fmt.Errorf("Duplicate metadata key: %v", metadata.Key)
		}
		metadataKeys[metadata.Key] = true
	}
	if err := errorIfUnknown(uc.UnknownFields); err != nil {
		return err
	}
	return nil
}

// Verifies that the given content type string is valid.
func validateContentTypeString(ct string) error {
	// TODO: verify that the content type is well formed.
	return nil
}

// Validate verifies that the configuration is well-formed.
func (ctc *ContentTypeConfig) Validate() error {
	// Treat fields like a "oneof"
	if ctc.Automatic != nil {
		if ctc.Automatic.Enabled && len(ctc.StaticValue) > 0 {
			return errors.New("Cannot set both 'static_value' and 'automatic.enabled: true' for Content Type.")
		}
		if ctc.Automatic.Enabled && ctc.Extraction != nil {
			return errors.New("Cannot set both 'extraction' and 'automatic.enabled: true' for Content Type.")
		}
	}
	if len(ctc.StaticValue) > 0 && ctc.Extraction != nil {
		return errors.New("Cannot set both 'extraction' and 'static_value' for Content Type.")
	}

	// Prevent use of unknown fields.
	if err := errorIfUnknown(ctc.UnknownFields); err != nil {
		return err
	}

	// Validate the one that is populated.
	if ctc.Automatic != nil {
		return ctc.Automatic.Validate()
	}
	if len(ctc.StaticValue) > 0 {
		return validateContentTypeString(ctc.StaticValue)
	}
	if ctc.Extraction != nil {
		return ctc.Extraction.Validate()
	}

	// If none are populated, we won't record a content type.
	return nil
}

// Validate verifies that the configuration is well-formed.
func (actc *AutoContentTypeConfig) Validate() error {
	// Disallow unknown fields.
	if err := errorIfUnknown(actc.UnknownFields); err != nil {
		return err
	}

	// Currently, there is no way to misconfigure this setting.
	return nil
}

// Validate verifies that the configuration is well-formed.
func (ec *ExtractionConfig) Validate() error {
	// Require a non-empty expression
	if len(ec.Expression) == 0 {
		return errors.New("Must specify a non-empty 'expression'.")
	}

	// Disallow unknown fields.
	if err := errorIfUnknown(ec.UnknownFields); err != nil {
		return err
	}

	// TODO: validate the actual contents of the expression
	return nil
}

// Validate verifies that the configuration is well-formed.
func (mlc *MetadataLabelConfig) Validate() error {
	if len(mlc.Key) == 0 {
		return errors.New("Label key cannot be empty.")
	}
	if mlc.Value == nil {
		return errors.New("Must specify a 'value' configuration.")
	}
	if err := errorIfUnknown(mlc.UnknownFields); err != nil {
		return err
	}
	return mlc.Value.Validate()
}

// Validate verifies that the configuration is well-formed.
func (mlvc *MetadataLabelValueConfig) Validate() error {
	// Enforce mutual exclusion of oneof options.
	if len(mlvc.StaticValue) > 0 && mlvc.Extraction != nil {
		return errors.New("Cannot set both 'extraction' and 'static_value' for label values.")
	}

	// Prevent presence of unknown fields.
	if err := errorIfUnknown(mlvc.UnknownFields); err != nil {
		return err
	}

	// Require that at least one option is set.
	if len(mlvc.StaticValue) == 0 && mlvc.Extraction == nil {
		return errors.New("Must set either 'static_value' or 'extraction'.")
	}

	// Validate the expression if present
	if mlvc.Extraction != nil {
		return mlvc.Extraction.Validate()
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
