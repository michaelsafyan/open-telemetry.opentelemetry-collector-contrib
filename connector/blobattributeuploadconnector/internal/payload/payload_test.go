// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "payload" manages the conversion from "Value" to
// the raw bytes which are to be uploaded for that value.
package payload

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"testing"
)

func toBytes(value pcommon.Value) ([]byte, error) {
	result, err := ValueToBytes(value)
	if err != nil {
		fmt.Printf("Failed to convert to bytes: %v\n", err)
	} else {
		fmt.Printf("Converted to bytes:\n%v\n", string(result))
	}
	return result, err
}

func fromJSON(b []byte) (pcommon.Map, error) {
	rawData := map[string]any{}
	if err := json.Unmarshal(b, &rawData); err != nil {
		fmt.Printf("Failed to unmarshal: %v\n", err)
		return pcommon.NewMap(), err
	}
	fmt.Printf("Loaded: %v\n", rawData)
	m := pcommon.NewMap()
	if err := m.FromRaw(rawData); err != nil {
		fmt.Printf("Failed to load map from raw: %v\n", err)
		return pcommon.NewMap(), err
	}
	return m, nil
}

func mapDebug(m pcommon.Map) string {
	elementCount := m.Len()
	var keys = []string{}
	m.Range(func(k string, v pcommon.Value) bool {
		keys = append(keys, k)
		return true
	})
	return fmt.Sprintf("%v elements, keys: %v", elementCount, keys)
}

func HasElement(m pcommon.Map, k string) bool {
	_, present := m.Get(k)
	return present
}

func GetInt(m pcommon.Map, k string) int {
	val, present := m.Get(k)
	if !present {
		panic(fmt.Sprintf("no such key: %v; map has %v\n", k, mapDebug(m)))
	}
	if val.Type() != pcommon.ValueTypeInt {
		if val.Type() == pcommon.ValueTypeDouble {
			return int(val.Double())
		}
		panic(fmt.Sprintf("not an integer: %v; actual type: %v\n", k, val.Type()))
	}
	return int(val.Int())
}

func GetStr(m pcommon.Map, k string) string {
	val, present := m.Get(k)
	if !present {
		panic(fmt.Sprintf("no such key: %v; map has %v\n", k, mapDebug(m)))
	}
	if val.Type() != pcommon.ValueTypeStr {
		panic(fmt.Sprintf("not a string: %v; actual type: %v\n", k, val.Type()))
	}
	return val.Str()
}

func TestHandlesStrings(t *testing.T) {
	value := pcommon.NewValueStr("foo")
	result, err := toBytes(value)
	assert.Equal(t, err, nil)
	assert.Equal(t, result, []byte("foo"))
}

func TestHandlesByteArray(t *testing.T) {
	value := pcommon.NewValueBytes()
	fromRawErr := value.FromRaw([]byte{1, 2, 3})
	assert.Equal(t, fromRawErr, nil)
	result, err := toBytes(value)
	assert.Equal(t, err, nil)
	assert.Equal(t, result, []byte{1, 2, 3})
}

func TestHandlesInt(t *testing.T) {
	value := pcommon.NewValueInt(12345)
	encoded, err := toBytes(value)
	assert.Equal(t, err, nil)

	mapData, decodeErr := fromJSON(encoded)
	assert.Equal(t, decodeErr, nil)
	assert.True(t, HasElement(mapData, "data"))
	assert.Equal(t, GetInt(mapData, "data"), 12345)
}

func TestHandlesMap(t *testing.T) {
	value := pcommon.NewValueMap()
	m := value.Map()
	m.PutStr("key1", "value1")
	m.PutStr("key2", "value2")

	encoded, err := toBytes(value)
	assert.Equal(t, err, nil)

	mapData, decodeErr := fromJSON(encoded)
	assert.Equal(t, decodeErr, nil)
	assert.True(t, HasElement(mapData, "key1"))
	assert.True(t, HasElement(mapData, "key2"))

	assert.Equal(t, GetStr(mapData, "key1"), "value1")
	assert.Equal(t, GetStr(mapData, "key2"), "value2")
}
