// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "blobuploadconnector" provides a connector that writes
// certain specified attributes/fields to a blob storage backend.
//
// The file "factory.go" file provides the logic that creates the connector.
package blobuploadconnector

import (
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/connector"

	"github.com/open-telemetry/opentelemetry-collector-contrib/connector/blobuploadconnector/internal/metadata"
)

func createDefaultConfig() component.Config {
	return &Config{
		UploadQueueSize:    1024,
		UploadTimeoutNanos: int64(5 * time.Second),
	}
}

func NewFactory() connector.Factory {
	return connector.NewFactory(
		metadata.Type,
		createDefaultConfig,
		connector.WithTracesToTraces(
			createTracesToTracesConnector,
			metadata.TracesToTracesStability))
}
