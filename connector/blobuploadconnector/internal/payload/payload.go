// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package "payload" manages the conversion from "Value" to
// the raw bytes which are to be uploaded for that value.
package payload

import (
	"encoding/json"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

func toJsonBytes(m pcommon.Map) ([]byte, error) {
	rawData := m.AsRaw()
	return json.Marshal(rawData)
}

func ValueToBytes(value pcommon.Value) ([]byte, error) {
	t := value.Type()

	if t == pcommon.ValueTypeBytes {
		return value.Bytes().AsRaw(), nil
	}

	if t == pcommon.ValueTypeStr {
		return []byte(value.Str()), nil
	}

	if t == pcommon.ValueTypeMap {
		return toJsonBytes(value.Map())
	}

	m := pcommon.NewMap()
	value.CopyTo(m.PutEmpty("data"))
	return toJsonBytes(m)
}
