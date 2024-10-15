// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "blobuploadconnector" provides a connector that writes
// certain specified attributes/fields to a blob storage backend.
//
// The file "config_traces.go" manages the subset of config options
// that relate to the logs signal type.
package blobuploadconnector

import (
	"errors"
	"fmt"
)

// "LogsConfig" defines how this connector should handle the logs signal type.
type LogsConfig struct {
	// Rules that apply to different groups of logs.
	Groups []*LogsConfigGroup `mapstructure:"groups"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Provides a common set of behaviors for a group of logs
type LogsConfigGroup struct {
	// Names the group of configuration.
	Name string `mapstructure:"name"`

	// Determines when a log belongs to this group. If omitted,
	// then all logs are considered to match and belong.
	MatchConfig *LogsMatchConfig `mapstructure:"match"`

	// Configuration regarding how to handle pieces of the body
	// for logs which belong to this group.
	BodyConfig *LogsBodyConfig `mapstructure:"body"`

	// Configuration regarding how to handle the attributes for
	// the logs which belong to this group.
	AttributeConfig *LogsAttributeConfig `mapstructure:"attributes"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Used to match/identify an entire log or set of logs.
type LogsMatchConfig struct {
	// Restricts the match to the specified combination of attributes.
	// If omitted, then logs with any attributes will be matched.
	Attributes []*LogAttributesMatcher `mapstructure:"attributes"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Used to filter logs to those matching a particular
// combination of attributes and values.
type LogAttributesMatcher struct {
	// The key that is being matched by the rule
	Key string `mapstructure:"key"`

	// If the key should be looked up from a limited
	// set of locations. Valid values include: "resource",
	// "scope", and "logrecord". One might use this field
	// to limit the set of locations under consideration; if
	// unset, then all locations are considered for matching.
	Locations []string `mapstructure:"locations"`

	// Governs what the value must be to match. If unset,
	// then the key is only required to be present.
	//
	// Mutually exclusive with "absent".
	Value *LogsAttributeValueMatcher `mapstructure:"value"`

	// If set and has a value of true, then the given key
	// must not be present for the log to match.
	//
	// Mutually exclusive with "value".
	Absent bool `mapstructure:"absent"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Used to match an attribute value.
type LogsAttributeValueMatcher struct {
	StringValue *LogsStringAttributeValueMatcher `mapstructure:"string_value"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Used to match a string-valued attribute value.
type LogsStringAttributeValueMatcher struct {
	Equals     *string `mapstructure:"equals"`
	StartsWith *string `mapstructure:"starts_with"`
	EndsWith   *string `mapstructure:"ends_with"`
	Contains   *string `mapstructure:"contains"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// "LogsBodyConfig" defines how to process the body of a log.
type LogsBodyConfig struct {
	// Individual entries, each applying to a different part of the body.
	Rule []*LogBodyConfigRule `mapstructure:"rules"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// "LogsAttributeConfig" defines how to handle the attributes of a log.
type LogsAttributeConfig struct {
	// Individual entries, each applying to a different key to match.
	Rule []*AttributeConfigRule `mapstructure:"rules"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// "LogsBodyConfigRule" describes a field path in the body to target.
type LogBodyConfigRule struct {
	// The name of this rule.
	Name string `mapstructure:"name"`

	// Describes what portion of the log body to match.
	Match *LogBodyMatchConfig `mapstructure:"match"`

	// Determines the kind of action to take for the matching field(s).
	Action *ActionConfig `mapstructure:"action"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// "LogBodyMatchConfig" describes how to target fields in the body.
type LogBodyMatchConfig struct {
	// Specifies a JMESPath query to indicate which fields to target.
	JMESPath string `mapstructure:"jmespath"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

func (lc *LogsConfig) Validate() error {
	for _, group := range lc.Groups {
		if err := group.Validate(); err != nil {
			return err
		}
	}
	if err := errorIfUnknown(lc.UnknownFields); err != nil {
		return err
	}
	return nil
}

func (lcg *LogsConfigGroup) Validate() error {
	if len(lcg.Name) == 0 {
		return errors.New("Must specify 'name' in LogsConfigGroup")
	}
	if lcg.MatchConfig != nil {
		if err := lcg.MatchConfig.Validate(); err != nil {
			return err
		}
	}
	if lcg.BodyConfig != nil {
		if err := lcg.BodyConfig.Validate(); err != nil {
			return err
		}
	}
	if lcg.AttributeConfig != nil {
		if err := lcg.AttributeConfig.Validate(); err != nil {
			return err
		}
	}
	if err := errorIfUnknown(lcg.UnknownFields); err != nil {
		return err
	}

	if lcg.BodyConfig == nil && lcg.AttributeConfig == nil {
		return fmt.Errorf("Must specify 'attributes' or 'body' in log config group '%v'.", lcg.Name)
	}

	if err := errorIfUnknown(lcg.UnknownFields); err != nil {
		return err
	}

	return nil
}

func (lmc *LogsMatchConfig) Validate() error {
	for _, attr := range lmc.Attributes {
		if err := attr.Validate(); err != nil {
			return err
		}
	}

	if err := errorIfUnknown(lmc.UnknownFields); err != nil {
		return err
	}

	return nil
}

func validateLogAttributeLocation(s string) error {
	if s == "resource" || s == "scope" || s == "logrecord" {
		return nil
	}
	return fmt.Errorf("Invalid log attribute location: '%v'; valid options are: ['resource', 'scope', 'logrecord'].", s)
}

func (lam *LogAttributesMatcher) Validate() error {
	if len(lam.Key) == 0 {
		return errors.New("Must specify a non-empty key")
	}

	for _, location := range lam.Locations {
		if err := validateLogAttributeLocation(location); err != nil {
			return err
		}
	}

	if lam.Value != nil && lam.Absent {
		return errors.New("Cannot specify both 'value:' and 'absent: true'.")
	}

	if lam.Value != nil {
		if err := lam.Value.Validate(); err != nil {
			return err
		}
	}

	if err := errorIfUnknown(lam.UnknownFields); err != nil {
		return err
	}

	return nil
}

func (lavm *LogsAttributeValueMatcher) Validate() error {
	if lavm.StringValue != nil {
		if err := lavm.StringValue.Validate(); err != nil {
			return err
		}
	}

	if err := errorIfUnknown(lavm.UnknownFields); err != nil {
		return err
	}
	return nil
}

func (lsavm *LogsStringAttributeValueMatcher) Validate() error {
	if lsavm.StartsWith != nil && *(lsavm.StartsWith) == "" {
		return errors.New("If set, 'starts_with' must not be empty.")
	}
	if lsavm.EndsWith != nil && *(lsavm.EndsWith) == "" {
		return errors.New("If set, 'ends_with' must not be empty.")
	}
	if lsavm.Contains != nil && *(lsavm.Contains) == "" {
		return errors.New("If set, 'contains' must not be empty.")
	}
	if err := errorIfUnknown(lsavm.UnknownFields); err != nil {
		return err
	}
	return nil
}

func (lbc *LogsBodyConfig) Validate() error {
	for _, rule := range lbc.Rule {
		if err := rule.Validate(); rule != nil {
			return err
		}
	}
	if err := errorIfUnknown(lbc.UnknownFields); err != nil {
		return err
	}
	return nil
}

func (lac *LogsAttributeConfig) Validate() error {
	for _, rule := range lac.Rule {
		if err := rule.Validate(); rule != nil {
			return err
		}
	}
	if err := errorIfUnknown(lac.UnknownFields); err != nil {
		return err
	}
	return nil
}

func (lbcr *LogBodyConfigRule) Validate() error {
	if lbcr.Name == "" {
		return errors.New("Must specify a name for the log body config rule")
	}
	if lbcr.Match != nil {
		if err := lbcr.Match.Validate(); err != nil {
			return err
		}
	}
	if lbcr.Action != nil {
		if err := lbcr.Action.Validate(); err != nil {
			return err
		}
	}
	if err := errorIfUnknown(lbcr.UnknownFields); err != nil {
		return err
	}
	return nil
}

func (lbmc *LogBodyMatchConfig) Validate() error {
	if lbmc.JMESPath == "" {
		return errors.New("Must specify a non-empty 'jmespath' query.")
	}
	if err := errorIfUnknown(lbmc.UnknownFields); err != nil {
		return err
	}
	return nil
}
