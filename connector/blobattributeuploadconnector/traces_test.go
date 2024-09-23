// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "blobattributeuploadconnector" provides a connector that writes
// certain specified attributes to a blob storage backend.
//
// The file "traces_test.go" validates the "traces.go" file.
package blobattributeuploadconnector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/otel/metric"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
	nooptrace "go.opentelemetry.io/otel/trace/noop"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
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
// Miscellaneous helpers
// -------------------------------------------------------

func isDeadlineExceeded(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		return false
	}

	currentTime := time.Now()
	diff := currentTime.Compare(deadline)
	return diff >= 0
}

func wakeUpAfter(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 60 * time.Second
	}
	currentTime := time.Now()
	return deadline.Sub(currentTime)
}

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
	calls   []*backendUploadCall
	waiters []func()
	result  error
	mutex   sync.Mutex
}

// From "BlobStorageBackend"
func (tbsb *testBlobStorageBackend) Upload(ctx context.Context, uri string, data []byte, metadata backend.UploadMetadata) error {
	tbsb.mutex.Lock()
	result := tbsb.result
	oldWaiters := tbsb.waiters
	tbsb.waiters = make([]func(), 0)
	tbsb.calls = append(tbsb.calls, &backendUploadCall{
		uri:      uri,
		data:     data,
		metadata: copyMetadata(metadata),
	})
	tbsb.mutex.Unlock()

	fmt.Print("testBlobStorageBackend: updated; notifying waiters\n")
	for _, waiter := range oldWaiters {
		waiter()
	}
	return result
}

// Used to prevent tests from hanging indefinitely when waiting
func (tbsb *testBlobStorageBackend) notifyAfter(t time.Duration) {
	go func() {
		time.Sleep(t)
		tbsb.notifyAll()
	}()
}
func (tbsb *testBlobStorageBackend) notifyAll() {
	tbsb.mutex.Lock()
	oldWaiters := tbsb.waiters
	tbsb.waiters = make([]func(), 0)
	tbsb.mutex.Unlock()
	for _, waiter := range oldWaiters {
		waiter()
	}
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

func (tbsb *testBlobStorageBackend) calledAtLeast(n int) func(*testBlobStorageBackend) bool {
	return func(inner *testBlobStorageBackend) bool {
		return inner.callCount() >= n
	}
}

func (tbsb *testBlobStorageBackend) waitUntil(ctx context.Context, pred func(*testBlobStorageBackend) bool) error {
	for !pred(tbsb) {
		if isDeadlineExceeded(ctx) {
			return errors.New("Deadline exceeded.")
		}
		wg := &sync.WaitGroup{}
		wg.Add(1)
		waitFunc := func() { wg.Done() }
		tbsb.mutex.Lock()
		tbsb.waiters = append(tbsb.waiters, waitFunc)
		tbsb.mutex.Unlock()
		if pred(tbsb) {
			return nil
		}
		fmt.Print("testBlobStorageBackend: waiting for condition\n")
		tbsb.notifyAfter(wakeUpAfter(ctx))
		wg.Wait()
	}
	return nil
}

// Instantiates the test backend.
func newTestBackend() *testBlobStorageBackend {
	return &testBlobStorageBackend{
		calls:   make([]*backendUploadCall, 0),
		waiters: make([]func(), 0),
		result:  nil,
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

	fmt.Print("testTracesConsumer: updated; notifying waiters\n")
	for _, waiter := range oldWaiters {
		waiter()
	}
	return result
}

// Used to prevent hanging indefinitely when waiting for a condition
func (tc *testTracesConsumer) notifyAfter(t time.Duration) {
	go func() {
		time.Sleep(t)
		tc.notifyAll()
	}()
}
func (tc *testTracesConsumer) notifyAll() {
	tc.mutex.Lock()
	oldWaiters := tc.waiters
	tc.waiters = make([]func(), 0)
	tc.mutex.Unlock()
	for _, waiter := range oldWaiters {
		waiter()
	}
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

func (tc *testTracesConsumer) waitUntil(ctx context.Context, pred func(*testTracesConsumer) bool) error {
	for !pred(tc) {
		if isDeadlineExceeded(ctx) {
			return errors.New("Deadline exceeded.")
		}
		wg := &sync.WaitGroup{}
		wg.Add(1)
		waitFunc := func() { wg.Done() }
		tc.mutex.Lock()
		tc.waiters = append(tc.waiters, waitFunc)
		tc.mutex.Unlock()
		if pred(tc) {
			return nil
		}
		fmt.Print("testTracesConsumer: waiting for condition\n")
		tc.notifyAfter(wakeUpAfter(ctx))
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

// Helper to triangulate problems with YAML
func prettyPrintYAMLWithError(s string, e error) {
	fmt.Printf("\n\n****** YAML Error ******\n\n%v\n\n", e)
	fmt.Printf("****** YAML Content ******\n\n")
	lines := strings.Split(s, "\n")
	for index, line := range lines {
		with_tabs_highlighted := strings.ReplaceAll(line, "\t", "[[!!TAB!!]]")
		line_number := index + 1
		fmt.Printf("    %3d  %v\n", line_number, with_tabs_highlighted)
	}
	fmt.Printf("\n\n")
}

// Helper to load the YAML content into the Config object
func yamlToConfig(s string, out *Config) error {
	rawParsedConfig := make(map[string]interface{})
	if err := yaml.Unmarshal([]byte(s), rawParsedConfig); err != nil {
		prettyPrintYAMLWithError(s, err)
		return err
	}
	if err := mapstructure.Decode(rawParsedConfig, out); err != nil {
		prettyPrintYAMLWithError(s, err)
		fmt.Printf("****** Parsed Content ******\n\n%v\n\n", rawParsedConfig)
		return err
	}
	return nil
}

func (tf *testFixture) Start(yamlConfig string) (*runningConnector, error) {
	factory := tf.createConnectorFactory()
	cfg := factory.CreateDefaultConfig()
	config := cfg.(*Config)
	if err := yamlToConfig(yamlConfig, config); err != nil {
		return nil, err
	}
	validationErr := componenttest.CheckConfigStruct(config)
	if validationErr != nil {
		return nil, validationErr
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
	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitCancel()
	assert.NoError(t, running.testConsumer.waitUntil(waitCtx, running.testConsumer.calledAtLeast(1)))

	assert.False(t, backend.wasCalled())
	assert.False(t, fixture.registry.wasCalled())
	assert.True(t, running.testConsumer.wasCalled())
	assert.Equal(t, data, running.testConsumer.lastCall())
}

func TestUploadsSpanAttributes(t *testing.T) {
	config := `
traces:
  attributes:
    rules:
    - name: http_requests
      match:
       key: http.request.body.content
      action:
       upload:
        destination_uri: mybackend://mybucket/${span.trace_id}/${span.span_id}/request.json
        content_type:
          static_value: application/json
`
	ctx := context.Background()
	backend := newTestBackend()
	fixture := newTestFixture(t)
	fixture.registry.setResult(backend)
	running, err := fixture.Start(config)
	assert.NoError(t, err)
	defer running.Stop()

	data := ptrace.NewTraces()
	resourceSpans := data.ResourceSpans().AppendEmpty()
	scopeSpans := resourceSpans.ScopeSpans().AppendEmpty()
	span := scopeSpans.Spans().AppendEmpty()
	testTraceID := pcommon.TraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	testSpanID := pcommon.SpanID([8]byte{8, 7, 6, 5, 4, 3, 2, 1})
	span.SetName("testspan")
	span.SetTraceID(testTraceID)
	span.SetSpanID(testSpanID)
	span.SetStartTimestamp(pcommon.Timestamp(1))
	span.SetEndTimestamp(pcommon.Timestamp(2))
	attributes := span.Attributes()
	attributes.PutStr("unchanged", "somevalue")
	attributes.PutStr("http.request.body.content", "{\"hello\": \"world\"}")

	assert.NoError(t, running.ConsumeTraces(ctx, data))

	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitCancel()
	assert.NoError(t, running.testConsumer.waitUntil(waitCtx, running.testConsumer.calledAtLeast(1)))
	assert.NoError(t, backend.waitUntil(waitCtx, backend.calledAtLeast(1)))

	assert.True(t, backend.wasCalled())
	assert.True(t, fixture.registry.wasCalled())
	assert.True(t, running.testConsumer.wasCalled())

	// Verify that the attribute value got uploaded as expected.
	uploadCall := backend.lastCall()
	assert.Equal(t, uploadCall.uri, "mybackend://mybucket/hex/hex/request.json")
	assert.Equal(t, uploadCall.data, []byte("{\"hello\": \"world\"}"))

	// Verify that no spans were added or removed.
	outputTraces := running.testConsumer.lastCall()
	outputResourceSpans := outputTraces.ResourceSpans()
	assert.Equal(t, outputResourceSpans.Len(), 1)
	outputResourceSpan := outputResourceSpans.At(0)
	outputScopeSpans := outputResourceSpan.ScopeSpans()
	assert.Equal(t, outputScopeSpans.Len(), 1)
	outputScopeSpan := outputScopeSpans.At(0)
	outputSpans := outputScopeSpan.Spans()
	assert.Equal(t, outputSpans.Len(), 1)
	outputSpan := outputSpans.At(0)

	// Verify that non-matching attributes were unchanged.
	outputAttributes := outputSpan.Attributes()
	unchangedVal, unchangedPresent := outputAttributes.Get("unchanged")
	assert.True(t, unchangedPresent)
	assert.Equal(t, unchangedVal, "somevalue")

	// Verify that other properties of the span are unchanged.
	assert.Equal(t, outputSpan.Name(), "testspan")
	assert.Equal(t, outputSpan.TraceID(), testTraceID)
	assert.Equal(t, outputSpan.SpanID(), testSpanID)
	assert.Equal(t, outputSpan.StartTimestamp(), span.StartTimestamp())
	assert.Equal(t, outputSpan.EndTimestamp(), span.EndTimestamp())

	// Verify that the replaced attribute is not present
	_, uploadedAttributePresent := outputAttributes.Get("http.request.body.content")
	assert.False(t, uploadedAttributePresent)

	// Verify that attributes for the URI and content type were added
	uriAttrValue, uriAttrPresent := outputAttributes.Get("http.request.body.content.ref.uri")
	typeAttrValue, typeAttrPresent := outputAttributes.Get("http.request.body.content.ref.content_type")
	assert.True(t, uriAttrPresent)
	assert.True(t, typeAttrPresent)
	assert.Equal(t, typeAttrValue.Str(), "application/json")
	assert.Equal(t, uriAttrValue.Str(), "mybackend://mybucket/hex/hex/request.json")
}

func TestUploadsSpanEventAttributes(t *testing.T) {
	config := `
traces:
	events:
	groups:
		- name: genai_prompts
		  event_name:
			match_if_any_equal_to:
			- gen_ai.content.prompt
		  attributes:
			rules:
			- name: genai_prompt_attribute
			match:
				key: gen_ai.prompt
				action:
				upload:
					destination_uri: mybackend://mybucket/${span.trace_id}/${span.span_id}/${event_index}/prompt.txt
					content_type:
                      static_value: text/plain
		- name: genai_responses
		  event_name:
			match_if_any_equal_to:
			- gen_ai.content.completion
		  attributes:
			rules:
			- name: genai_response_attribute
			match:
				key: gen_ai.completion
				action:
				upload:
					destination_uri: mybackend://mybucket/${span.trace_id}/${span.span_id}/${event_index}/response.json
					content_type:
                      static_value: application/json
`
	ctx := context.Background()
	backend := newTestBackend()
	fixture := newTestFixture(t)
	fixture.registry.setResult(backend)
	running, err := fixture.Start(config)
	assert.NoError(t, err)
	defer running.Stop()

	data := ptrace.NewTraces()
	assert.NoError(t, running.ConsumeTraces(ctx, data))
	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitCancel()
	assert.NoError(t, running.testConsumer.waitUntil(waitCtx, running.testConsumer.calledAtLeast(1)))

	assert.False(t, backend.wasCalled())
	assert.False(t, fixture.registry.wasCalled())
	assert.True(t, running.testConsumer.wasCalled())
	assert.Equal(t, data, running.testConsumer.lastCall())
}
