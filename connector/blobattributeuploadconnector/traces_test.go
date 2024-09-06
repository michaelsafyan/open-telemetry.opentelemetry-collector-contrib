// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "blobattributeuploadconnector" provides a connector that writes
// certain specified attributes to a blob storage backend.
//
// The file "traces_test.go" validates the "traces.go" file.
package blobattributeuploadconnector

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/open-telemetry/opentelemetry-collector-contrib/connector/blobattributeuploadconnector/internal/backend"
)

// -------------------------------------------------------
// Mocking "backend.Registry", "backend.BlobStorageBackend"
// -------------------------------------------------------

// Used to record the contents of "UploadMetadata".
type testUploadMetadata struct {
	contentType string
	labels      map[string]string
}

// Make "testUploadMetadata" conform to "UploadMetadata".
func (tum *testUploadMetadata) ContentType() string {
	return tum.contentType
}
func (tum *testUploadMetadata) Labels() map[string]string {
	return tum.labels
}

// Used to record a snapshot of upload metadata whose lifetime is
// not guaranteed beyond the scope in which the snapshot is being made.
func copyMetadata(um backend.UploadMetadata) backend.UploadMetadata {
	return &testUploadMetadata{
		contentType: um.ContentType(),
		labels:      um.Labels(),
	}
}

// Record of the paramemeters to "backend.BlobStorageBackend.Upload"
type backendUploadCall struct {
	uri      string
	data     []byte
	metadata backend.UploadMetadata
}

// Implementation of "BlobStorageBackend" that records calls.
type testBlobStorageBackend struct {
	calls  []*backendUploadCall
	result error
	mutex  sync.Mutex
}

// From "BlobStorageBackend"
func (tbsb *testBlobStorageBackend) Upload(ctx context.Context, uri string, data []byte, metadata UploadMetadata) error {
	tbsb.mutex.Lock()
	defer tbsb.mutex.Unlock()

	tbsb.calls = append(tbsb.calls, &backendUploadCall{
		uri:      uri,
		data:     data,
		metadata: copyMetadata(metadata),
	})
	return tbsb.result
}

func (tbsb *testBlobStorageBackend) callCount() int {
	tbsb.mutex.Lock()
	defer tbsb.mutex.Unlock()
	return len(tbsb.calls)
}

func (tbsb *testBlobStorageBackend) getCall(i int) *backendUploadCall {
	tbsb.mutex.Lock()
	defer tbsb.mutex.Unlock()
	return tbsb.calls[i]
}

func (tbsb *testBlobStorageBackend) wasCalled() bool {
	return tbsb.callCount() > 0
}

func (tbsb *testBlobStorageBackend) lastCall() *backendUploadCall {
	return tbsb.getCall(tbsb.callCount() - 1)
}

// Convenience function for modifying expected result.
func (tbsb *testBlobStorageBackend) setResult(e error) {
	tbsb.mutex.Lock()
	defer tbsb.mutex.Unlock()

	tbsb.result = e
}

// Instantiates the test backend.
func newTestBackend() *testBlobStorageBackend {
	return &testBlobStorageBackend{
		calls:  make([]*backendUploadCall),
		result: nil,
	}
}

// Test implementation of "backend.Registry"
type testRegistry struct {
	calls         []string
	resultBackend backend.BlobStorageBackend
	resultError   error
	mutex         sync.Mutex
}

func (tr *testRegistry) GetBackendForURI(uri string) (BlobStorageBackend, error) {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()

	tr.calls = append(tr.calls, uri)
	return tr.resultBackend, tr.resultError
}

func (tr *testRegistry) setResult(b backend.BlobStorageBackend) {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()

	tr.resultBackend = b
	tr.resultError = nil
}

func (tr *testRegistry) setError(e error) {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()

	tr.resultBackend = nil
	tr.resultError = e
}

func (tr *testRegistry) callCount() int {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()
	return len(tr.calls)
}

func (tr *testRegistry) getCall(i int) string {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()
	return tr.calls[i]
}

func (tr *testRegistry) wasCalled() bool {
	return tr.callCount() > 0
}

func (tr *testRegistry) lastCall() string {
	return tr.getCall(tr.callCount() - 1)
}

func newTestRegistry() *testRegistry {
	return &testRegistry{
		calls:         make([]string),
		resultBackend: newTestBackend(),
		resultError:   nil,
	}
}

// -------------------------------------------------------
// Mocking "consumer.Traces"
// -------------------------------------------------------

type testTraceConsumer struct {
	calls  []ptrace.Traces
	result error
	mutex  sync.Mutex
}

func (tc *testTracesConsumer) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	tc.calls = append(tc.calls, td)
	return tc.result
}

func (tc *testTracesConsumer) setResult(e error) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
}

func (tc *testTracesConsumer) toConsumer() (consumer.Traces, error) {
	return consumer.NewTraces(func(ctx context.Context, td ptrace.Traces) error {
		return tc.ConsumeTraces(ctx, td)
	})
}

func newTestTraceConsumer() *testTraceConsumer {
	return &testTraceConsumer{
		calls:  make([]ptrace.Traces),
		result: nil,
	}
}

// -------------------------------------------------------
// Defining a common test fixture for the tests.
// -------------------------------------------------------

type testFixture struct {
	t        *testing.T
	registry *testRegistry
}

func newTestFixture(t *testing.T) *testFixture {
	return &testFixture{
		t:        t,
		registry: newTestRegistry(),
	}
}

func (tf *testFixture) createConnectorFactory() connector.Factory {
	return connector.NewFactory(
		metadata.Type,
		createDefaultConfig,
		connector.WithTracesToTraces(
			func(ctx context.Context, settings connector.Settings, config component.Config, nextConsumer consumer.Traces) (Traces, error) {
				return createTracesToTracesConnectorWithRegistryFactory(
					ctx,
					settings,
					config,
					nextConsumer,
					tf.registry,
				)
			},
			metadata.TracesToTracesStability))
}

type runningConnector struct {
	tracesToTraces consumer.Traces
	testConsumer   *testTracesConsumer
}

func (rc *runningConnector) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	return rc.tracesToTraces.ConsumeTraces(ctx, td)
}

func (rc *runningConnector) Stop() {
	rc.tracesToTraces.Shutdown(context.Background())
}

func (tf *testFixture) Start(yamlConfig string) (*runningConnector, error) {
	factory := tf.createConnectorFactory()
	config := factory.createDefaultConfig()
	if err := yaml.Unmarshal([]byte(yamlConfig), &config); err != nil {
		return nil, err
	}
	testConsumer := newTestTraceConsumer()
	testConsumerAdaptor, testConsumerAdaptorErr := testConsumer.toConsumer()
	if testConsumerAdaptorErr != nil {
		return nil, testConsumerAdaptorErr
	}
	connector, connectorErr = factory.CreateTracesToTraces(
		context.Background(),
		connector.Settings{
			ID: testID,
		},
		config,
		testConsumerAdaptor)
	if connectorErr != nil {
		return nil, connectorErr
	}
	host := componenttest.NewNoOpHost()
	if startErr := connector.Start(context.Background(), host); startErr != nil {
		return nil, startErr
	}
	return &runningConnector{
		tracesToTraces: connector,
		testConsumer:   testConsumer,
	}, nil
}

// -------------------------------------------------------
// Testing logic
// -------------------------------------------------------

func TestActsAsPassThroughWithoutTraceConfig(t *testing.T) {
	ctx := context.Background()
	backend := newTestBackend()
	fixture := newTestFixture()
	fixture.registry.setResult(backend)
	running, err := fixture.Start("")
	assert.NoError(t, err)
	defer running.Stop()

	data := ptrace.NewTraces()
	assert.NoError(t, running.ConsumeTraces(ctx, data))
	assert.False(t, backend.wasCalled())
	assert.False(fixture.registry.wasCalled())
	assert.True(running.testConsumer.wasCalled())
	assert.Equal(t, data, testConsumer.lastCall())
}
