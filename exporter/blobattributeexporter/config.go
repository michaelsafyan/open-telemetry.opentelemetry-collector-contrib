// Package "blobattributeexporter" provides an exporter that writes
// certain specified attributes to a blob storage backend.
//
// The file "config.go" manages interaction with config options.
package blobattributeexporter

// "Config" defines the configuration structure for this exporter.
type Config struct {
	// Configuration regarding how this should apply to the traces signal.
	Traces TracesConfig `mapstructure:"traces"`
}

// "TracesConfig" defines how this exporter should handle the traces signal.
type TracesConfig struct {
	// Configuration regarding the handling of trace attributes.
	AttributeConfig TraceAttributeConfig `mapstructure:"attributes"`
}

// "TraceAttributeConfig" governs the handling of attribute information in
// trace telemetry data (as oppposed to event attributes).
type TraceAttributeConfig struct {
	// Individual entries, each applying to a different key to match.
	Rule []AttributeConfigRule `mapstructure:"rules"`
}

// "AttributeConfigRule" defines the handling of a single attribute.
type AttributeConfigRule struct {
	// Identifies the rule that is being handled.
	Name string `mapstructure:"name"`

	// Determines which attribute should be matched by the rule.
	Match MatchConfig `mapstructure:"match"`

	// Determines the kind of action to take for the matching attribute.
	Action ActionConfig `mapstructure:"action"`
}

// "MatchConfig" defines how to determine if an attribute should be processed.
type MatchConfig struct {
	// The name of the attribute that should be matched
	Key string `mapstructure:"key"`

	// If specified, match the specified key only in the
	// given locations (e.g. "span", "scope", "resource"). 
	Locations []string `mapstructure:"locations"`
}

// "ActionConfig" defines the kind of action which should be taken.
type ActionConfig struct {
	// If only a subset of the matched keys should be handled.
	Sampling SamplingConfig `mapstructure:"sample"`

	// How to upload the sampled content.
	Upload UploadConfig `mapstructure:"upload"`
}

// "SamplingConfig" defines how to handle sampling.
type SamplingConfig struct {
	// Whether downsampling is enabled.
	Enabled bool `mapstructure:"enabled"`

	// What percentage number ([0, 100]) to sample. 
	Percent int `mapstructure:"percent"`
}

// Describes how to upload the content to the blob storage.
type UploadConfig struct {
	// Where to write the configuration.
	DestinationUri string `mapstructure:"destination_uri"`
	
	// What content type to use in the metadata.
	ContentType ContentTypeConfig `mapstructure:"content_type"`
	
	// Additional metadata to attach to the uploaded content.
	MetadataLabels []MetadataLabelConfig `mapstructure:"labels"`
}

// Configures how the content type will be determined.
type ContentTypeConfig struct {
	// Configures automatic content-type inference. 
	Automatic AutoContentTypeConfig `mapstructure:"automatic"`

	// Allows the content type to be specified from a static string.
	StaticValue string `mapstructure:"static_value"`

	// Allows the content type to be extracted from other properties.
	Extraction ExtractionConfig `mapstructure:"extraction"`
}

// Configuration for automatic content type inference.
type AutoContentTypeConfig struct {
	// Whether to enable the automatic content type inference.
	Enabled bool `mapstructure:"enabled"`
}

// Configures how to extract some piece of information.
type ExtractionConfig struct {
	// The expression that is to be evaluated.
	Expression string `mapstructure:"expression"`
}

// Configures how to add a metadata label to the uploaded file.
type MetadataLabelConfig struct {
	// The key of the metadata property.
	Key string `mapstructure:"key"`

	// The value of the metadata property.
	Value MetdataLabelValueConfig `mapstructure:"value"`
}

// Configures how to set the value of the property.
type MetadataLabelValueConfig struct {
	// Allows the label value to be specified from a static string.
	StaticValue string `mapstructure:"static_value"`

	// Allows the label value to be extracted from other properties.
	Extraction ExtractionConfig `mapstructure:"extraction"`
}

// Verifies that the configuration is valid.
func (c *Config) Validate() error {
	if err := c.TracesConfig.Validate() ; err != nil {
		return err
	}
	return nil
}

// Verifies that the configuration is valid.
func (tc *TracesConfig) Validate() error {
	if err := c.AttributeConfig.Validate() ; err != nil {
		return err
	}
	return nil
}

// Helper for "TraceAttributeConfig.Validate()" below.
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

// Verifies that the configuration is valid.
func (tac *TraceAttributeConfig) Validate() error {
	for _, rule := range tac.Rule {
		if err := rule.Validate() ; err != nil {
			return err
		}
		for _, location := range rule.Match.Locations {
			if err := validateTraceLocation(rule.name, location) ; err != nil {
				return err
			}
		}
	}
	return nil
}

// Verifies that the configuration is valid.
func (acr *AttributeConfigRule) Validate() error {
	// TODO: implement
	return nil
}

// Verifies that the configuration is valid.
func (mc *MatchConfig) Validate() error {
	// TODO: implement
	return nil
}

// Verifies that the configuration is valid.
func (ac *ActionConfig) Validate() error {
	// TODO: implement
	return nil
}

// Verifies that the configuration is valid.
func (sc *SamplingConfig) Validate() error {
	// TODO: implement
	return nil
}

// Verifies that the configuration is valid.
func (uc *UploadConfig) Validate() error {
	// TODO: implement
	return nil
}

// Verifies that the configuration is valid.
func (ctc *ContentTypeConfig) Validate() error {
	// TODO: implement
	return nil
}

// Verifies that the configuration is valid.
func (actc *AutoContentTypeConfig) Validate() error {
	// TODO: implement
	return nil
}

// Verifies that the configuration is valid.
func (ec *ExtractionConfig) Validate() error {
	// TODO: implement
	return nil
}

// Verifies that the configuration is valid.
func (mlc *MetadataLabelConfig) Validate() error {
	// TODO: implement
	return nil
}

// Verifies that the configuration is valid.
func (mlvc *MetadataLabelValueConfig) Validate() error {
	// TODO: implement
	return nil
}
