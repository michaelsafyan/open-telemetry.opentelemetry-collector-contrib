// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "blobuploadconnector" provides a connector that writes
// certain specified attributes/fields to a blob storage backend.
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

	// Configuration regarding how this should apply to the logs signal.
	Logs *LogsConfig `mapstructure:"logs"`

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
