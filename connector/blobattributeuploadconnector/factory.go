// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "blobattributeuploadconnector" provides a connector that writes
// certain specified attributes to a blob storage backend.
//
// The file "factory.go" file provides the logic that creates the connector.
package blobattributeuploadconnector

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/connector"
	"go.opentelemetry.io/collector/consumer"
)

const (
	typeStr = "blobattributeuploadconnector"
)

func createDefaultConfig() *component.Config {
	return &Config{}
}

func NewFactory() connector.Factory {
	return connector.NewFactory(
		typeStr,
		createDefaultConfig,
		connector.WithTracesToTraces(
			createTracesToTracesConnector,
			component.StabilityLevelAlpha))
}
