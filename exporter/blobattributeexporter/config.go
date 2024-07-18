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
	names := map[string]bool
	for _, rule := range tac.Rule {
		if err := rule.Validate() ; err != nil {
			return err
		}
		if _, found := names[rule.Name] ; found {
			return fmt.Errorf("Rule name %v found more than once.", rule.Name)
		}
		names[rule.Name] = true
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
	if len(acr.Name) == 0 {
		return errors.New("Missing required name for config rule.")
	}
	if err := acr.Match.Validate() ; err != nil {
		return err
	}
	if err := acr.Action.Validate() ; err != nil {
		return err
	}
	return nil
}

// Verifies that the configuration is valid.
func (mc *MatchConfig) Validate() error {
	if len(mc.Key) == 0  {
		return errors.New("Missing required key in match configuration.")
	}
	return nil
}

// Verifies that the configuration is valid.
func (ac *ActionConfig) Validate() error {
	if err := ac.Sampling.Validate() ; err != nil {
		return err
	}
	if err := ac.UploadConfig.Validate() ; err != nil {
		return err
	}
	return nil
}

// Verifies that the configuration is valid.
func (sc *SamplingConfig) Validate() error {
	if sc.Percent < 0 || sc.Percent > 100 {
		return fmt.Errorf("Invalid percentage: %v", sc.Percent)
	}
	return nil
}

// Verifies that the configuration is valid.
func (uc *UploadConfig) Validate() error {
	if len(uc.DestinationUri) == 0 {
		return errors.New("Destination URI must not be empty.")
	}
	if err := uc.ContentType.Validate() ; err != nil {
		return err
	}
	metadataKeys := map[string]bool
	for _, metadata := range uc.MetadataLabelConfig {
		if err := metadata.Validate() ; err != nil {
			return err
		}
		if _, found := metadataKeys[metadata.Key] ; if found {
			return errors.New("Duplicate metadata key: %v", metadata.Key)
		}
		metadataKeys[metadata.Key] = true
	}
	return nil
}

// Verifies that the given content type string is valid.
func validateContentTypeString(ct string) error {
	// TODO: verify that the content type is well formed.
	return nil
}

// Verifies that the configuration is valid.
func (ctc *ContentTypeConfig) Validate() error {
	// Treat fields like a "oneof"
	if ctc.Automatic.Enabled && len(ctc.StaticValue) > 0 {
		return errors.New("Cannot set both 'static_value' and 'automatic.enabled: true' for Content Type.")
	}
	if ctc.Automatic.Enabled && len(ctc.Extraction.Expression) > 0 {
		return errors.New("Cannot set both 'extraction.expression' and 'automatic.enabled: true' for Content Type.")
	}
	if len(ctc.StaticValue) > 0 && len(ctc.Extraction.Expression) > 0 {
		return errors.New("Cannot set both 'extraction.expression' and 'static_value' for Content Type.")
	}

	// Validate the one that is populated.
	if ctc.Automatic.Enabled {
		return ctc.Automatic.Validate()
	}
	if len(ctc.StaticValue) > 0 {
		return validateContentTypeString(ctx.StaticValue)
	}
	if len(ctc.Extraction.Expression) > 0 {
		return ctc.Extraction.Validate()
	}

	// If none are populated, we won't record a content type.
	return nil
}


// Verifies that the configuration is valid.
func (actc *AutoContentTypeConfig) Validate() error {
	// Currently, there is no way to misconfigure this setting.
	return nil
}

// Verifies that the configuration is valid.
func (ec *ExtractionConfig) Validate() error {
	// TODO: implement
	return nil
}

// Verifies that the configuration is valid.
func (mlc *MetadataLabelConfig) Validate() error {
	if len(mlc.Key) == 0 {
		return errors.New("Label key cannot be empty.")
	}
	return mlc.Value.Validate()
}

// Verifies that the configuration is valid.
func (mlvc *MetadataLabelValueConfig) Validate() error {
	// Enforce mutual exclusion of oneof options.
	if len(mlvc.StaticValue) > 0  && len(mlvc.Extraction.Expression) > 0 {
		return errors.New("Cannot set both 'extraction.expression' and 'static_value' for label values.")
	}

	// Require that at least one option is set.
	if len(mlvc.StaticValue) == 0 && len(mlvc.Extraction.Expression) == 0 {
		return errors.New("Must set either 'static_value' or 'extraction.expression'.")
	}

	// Validate the expression if present
	if len(mlvc.Extraction.Expression) {
		return mlvc.Extraction.Validate()
	}

	return nil
}
