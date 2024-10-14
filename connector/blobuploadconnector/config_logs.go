// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "blobuploadconnector" provides a connector that writes
// certain specified attributes/fields to a blob storage backend.
//
// The file "config_traces.go" manages the subset of config options
// that relate to the logs signal type.
package blobuploadconnector

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
	// Restricts the match to the specified severities. If omitted,
	// then any severity value will be matched.
	Severity *LogSeverityMatcher `mapstructure:"severity"`

	// Restricts the match to the specified combination of attributes.
	// If omitted, then logs with any attributes will be matched.
	Attributes []*LogAttributesMatcher `mapstructure:"attributes"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Used to filter logs to a specific range of severities.
type LogSeverityMatcher struct {
	// If set, severity must be at least this value (inclusive).
	MinSeverity string `mapstructure:"min"`

	// If set, severity must be at most this value (inclusive).
	MaxSeverity string `mapstructure:"max"`

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
	StringValue *LogsStringAttriubteValueMatcher `mapstructure:"string_value"`

	// Any fields which did not fall into the defined structure.
	UnknownFields map[string]interface{} `mapstructure:",remain"`
}

// Used to match a string-valued attribute value.
type LogsStringAttriubteValueMatcher struct {
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
}
