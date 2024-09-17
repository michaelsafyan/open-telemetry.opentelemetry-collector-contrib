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

	"go.uber.org/zap"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/otel/metric"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
	nooptrace "go.opentelemetry.io/otel/trace/noop"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configtelemetry"
	"go.opentelemetry.io/collector/connector"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/open-telemetry/opentelemetry-collector-contrib/connector/blobattributeuploadconnector/internal/backend"
	"github.com/open-telemetry/opentelemetry-collector-contrib/connector/blobattributeuploadconnector/internal/metadata"

	"gopkg.in/yaml.v3"
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
func (tbsb *testBlobStorageBackend) Upload(ctx context.Context, uri string, data []byte, metadata backend.UploadMetadata) error {
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
		calls:  make([]*backendUploadCall, 0),
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

func (tr *testRegistry) GetBackendForURI(uri string) (backend.BlobStorageBackend, error) {
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
		calls:         make([]string, 0),
		resultBackend: newTestBackend(),
		resultError:   nil,
	}
}

// -------------------------------------------------------
// Mocking "backendRegistryFactory"
// -------------------------------------------------------

type testBackendRegistryFactory struct {
	resultRegistry backend.Registry
	resultError    error
	calls          int
	mutex          sync.Mutex
}

func newTestBackendRegistryFactory() *testBackendRegistryFactory {
	return &testBackendRegistryFactory{
		resultRegistry: newTestRegistry(),
		resultError:    nil,
		calls:          0,
	}
}

func (tbrf *testBackendRegistryFactory) setBackendRegistry(br backend.Registry) {
	tbrf.mutex.Lock()
	defer tbrf.mutex.Unlock()
	tbrf.resultError = nil
	tbrf.resultRegistry = br
}

func (tbrf *testBackendRegistryFactory) setError(e error) {
	tbrf.mutex.Lock()
	defer tbrf.mutex.Unlock()
	tbrf.resultError = e
	tbrf.resultRegistry = nil
}

func (tbrf *testBackendRegistryFactory) createRegistry() (backend.Registry, error) {
	tbrf.mutex.Lock()
	defer tbrf.mutex.Unlock()
	tbrf.calls++
	return tbrf.resultRegistry, tbrf.resultError
}

func (tbrf *testBackendRegistryFactory) callCount() int {
	tbrf.mutex.Lock()
	defer tbrf.mutex.Unlock()
	return tbrf.calls
}

func (tbrf *testBackendRegistryFactory) wasCalled() bool {
	return tbrf.callCount() > 0
}

// -------------------------------------------------------
// Mocking "component.Host"
// -------------------------------------------------------

type testHost struct {
	extensionsMap map[component.ID]component.Component
}

func (th *testHost) GetExtensions() map[component.ID]component.Component {
	return th.extensionsMap
}

func newTestHost() *testHost {
	return &testHost{
		extensionsMap: make(map[component.ID]component.Component),
	}
}

// -------------------------------------------------------
// Mocking "consumer.Traces"
// -------------------------------------------------------

type testTracesConsumer struct {
	calls   []ptrace.Traces
	waiters []func()
	result  error
	mutex   sync.Mutex
}

func (tc *testTracesConsumer) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	tc.mutex.Lock()
	result := tc.result
	tc.calls = append(tc.calls, td)
	oldWaiters := tc.waiters
	tc.waiters = make([]func(), 0)
	tc.mutex.Unlock()

	for _, waiter := range oldWaiters {
		waiter()
	}
	return result
}

func (tc *testTracesConsumer) setResult(e error) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.result = e
}

func (tc *testTracesConsumer) toConsumer() (consumer.Traces, error) {
	return consumer.NewTraces(func(ctx context.Context, td ptrace.Traces) error {
		return tc.ConsumeTraces(ctx, td)
	})
}

func (tc *testTracesConsumer) callCount() int {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	return len(tc.calls)
}

func (tc *testTracesConsumer) wasCalled() bool {
	return tc.callCount() > 0
}

func (tc *testTracesConsumer) lastCall() ptrace.Traces {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	return tc.calls[len(tc.calls)-1]
}

func (tc *testTracesConsumer) calledAtLeast(n int) func(*testTracesConsumer) bool {
	return func(tcinner *testTracesConsumer) bool {
		return tcinner.callCount() >= n
	}
}

func (tc *testTracesConsumer) waitUntil(pred func(*testTracesConsumer) bool) error {
	for !pred(tc) {
		wg := &sync.WaitGroup{}
		wg.Add(1)
		waitFunc := func() { wg.Done() }
		tc.mutex.Lock()
		tc.waiters = append(tc.waiters, waitFunc)
		tc.mutex.Unlock()
		if pred(tc) {
			return nil
		}
		wg.Wait()
	}
	return nil
}

func newTestTracesConsumer() *testTracesConsumer {
	return &testTracesConsumer{
		calls:   make([]ptrace.Traces, 0),
		waiters: make([]func(), 0),
		result:  nil,
	}
}

// -------------------------------------------------------
// Defining a common test fixture for the tests.
// -------------------------------------------------------

type testFixture struct {
	t               *testing.T
	registry        *testRegistry
	registryFactory *testBackendRegistryFactory
	logger          *zap.Logger
	settings        component.TelemetrySettings
}

func newTestFixture(t *testing.T) *testFixture {
	logger, loggerError := zap.NewDevelopment()
	if loggerError != nil {
		panic(loggerError)
	}
	registry := newTestRegistry()
	registryFactory := newTestBackendRegistryFactory()
	registryFactory.setBackendRegistry(registry)
	return &testFixture{
		t:               t,
		registry:        registry,
		registryFactory: registryFactory,
		logger:          logger,
		settings: component.TelemetrySettings{
			Logger: logger,
			LeveledMeterProvider: func(_ configtelemetry.Level) metric.MeterProvider {
				return noopmetric.NewMeterProvider()
			},
			TracerProvider: nooptrace.NewTracerProvider(),
			MeterProvider:  noopmetric.NewMeterProvider(),
			MetricsLevel:   configtelemetry.LevelNone,
			Resource:       pcommon.NewResource(),
		},
	}
}

func (tf *testFixture) createConnectorFactory() connector.Factory {
	return connector.NewFactory(
		metadata.Type,
		createDefaultConfig,
		connector.WithTracesToTraces(
			func(ctx context.Context, settings connector.Settings, config component.Config, nextConsumer consumer.Traces) (connector.Traces, error) {
				return createTracesToTracesConnectorWithRegistryFactory(
					ctx,
					settings,
					config,
					nextConsumer,
					tf.registryFactory,
				)
			},
			metadata.TracesToTracesStability))
}

type runningConnector struct {
	tracesToTraces connector.Traces
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
	config := factory.CreateDefaultConfig()
	if err := yaml.Unmarshal([]byte(yamlConfig), &config); err != nil {
		return nil, err
	}
	testConsumer := newTestTracesConsumer()
	testConsumerAdaptor, testConsumerAdaptorErr := testConsumer.toConsumer()
	if testConsumerAdaptorErr != nil {
		return nil, testConsumerAdaptorErr
	}
	connectorResult, connectorErr := factory.CreateTracesToTraces(
		context.Background(),
		connector.Settings{
			ID:                component.MustNewIDWithName("blobattributeuploadconnector", tf.t.Name()),
			TelemetrySettings: tf.settings,
		},
		config,
		testConsumerAdaptor)
	if connectorErr != nil {
		return nil, connectorErr
	}
	host := newTestHost()
	if startErr := connectorResult.Start(context.Background(), host); startErr != nil {
		return nil, startErr
	}
	return &runningConnector{
		tracesToTraces: connectorResult,
		testConsumer:   testConsumer,
	}, nil
}

// -------------------------------------------------------
// Testing logic
// -------------------------------------------------------

func TestActsAsPassThroughWithoutTraceConfig(t *testing.T) {
	ctx := context.Background()
	backend := newTestBackend()
	fixture := newTestFixture(t)
	fixture.registry.setResult(backend)
	running, err := fixture.Start("")
	assert.NoError(t, err)
	defer running.Stop()

	data := ptrace.NewTraces()
	assert.NoError(t, running.ConsumeTraces(ctx, data))
	assert.NoError(t, running.testConsumer.waitUntil(running.testConsumer.calledAtLeast(1)))

	assert.False(t, backend.wasCalled())
	assert.False(t, fixture.registry.wasCalled())
	assert.True(t, running.testConsumer.wasCalled())
	assert.Equal(t, data, running.testConsumer.lastCall())
}
