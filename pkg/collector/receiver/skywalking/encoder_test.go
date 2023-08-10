// Tencent is pleased to support the open source community by making
// 蓝鲸智云 - 监控平台 (BlueKing - Monitor) available.
// Copyright (C) 2022 THL A29 Limited, a Tencent company. All rights reserved.
// Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://opensource.org/licenses/MIT
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package skywalking

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	conventions "go.opentelemetry.io/collector/semconv/v1.8.0"
	common "skywalking.apache.org/repo/goapi/collect/common/v3"
	agentV3 "skywalking.apache.org/repo/goapi/collect/language/agent/v3"
)

func TestSetInternalSpanStatus(t *testing.T) {
	tests := []struct {
		name   string
		swSpan *agentV3.SpanObject
		dest   ptrace.SpanStatus
		code   ptrace.StatusCode
	}{
		{
			name: "StatusCodeError",
			swSpan: &agentV3.SpanObject{
				IsError: true,
			},
			dest: generateTracesOneEmptyResourceSpans().Status(),
			code: ptrace.StatusCodeError,
		},
		{
			name: "StatusCodeOk",
			swSpan: &agentV3.SpanObject{
				IsError: false,
			},
			dest: generateTracesOneEmptyResourceSpans().Status(),
			code: ptrace.StatusCodeOk,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setInternalSpanStatus(test.swSpan, test.dest)
			assert.Equal(t, test.code, test.dest.Code())
		})
	}
}

func TestSwKvPairsToInternalAttributes(t *testing.T) {
	tests := []struct {
		name   string
		swSpan *agentV3.SegmentObject
		dest   ptrace.Span
	}{
		{
			name:   "mock-sw-swgment-1",
			swSpan: mockGrpcTraceSegment(1),
			dest:   generateTracesOneEmptyResourceSpans(),
		},
		{
			name:   "mock-sw-swgment-2",
			swSpan: mockGrpcTraceSegment(2),
			dest:   generateTracesOneEmptyResourceSpans(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			swKvPairsToInternalAttributes(test.swSpan.GetSpans()[0].Tags, test.dest.Attributes())
			assert.Equal(t, test.dest.Attributes().Len(), len(test.swSpan.GetSpans()[0].Tags))
			for _, tag := range test.swSpan.GetSpans()[0].Tags {
				value, _ := test.dest.Attributes().Get(tag.Key)
				assert.Equal(t, tag.Value, value.AsString())
			}
		})
	}
}

func TestSwProtoToTraces(t *testing.T) {
	tests := []struct {
		name   string
		swSpan *agentV3.SegmentObject
		dest   ptrace.Traces
		code   ptrace.StatusCode
	}{
		{
			name:   "mock-sw-swgment-1",
			swSpan: mockGrpcTraceSegment(1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			td := EncodeTraces(test.swSpan, "", nil)
			assert.Equal(t, 1, td.ResourceSpans().Len())
			assert.Equal(t, 2, td.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		})
	}
}

func TestSwReferencesToSpanLinks(t *testing.T) {
	tests := []struct {
		name   string
		swSpan *agentV3.SegmentObject
		dest   ptrace.Span
	}{
		{
			name:   "mock-sw-swgment-1",
			swSpan: mockGrpcTraceSegment(1),
			dest:   generateTracesOneEmptyResourceSpans(),
		},
		{
			name:   "mock-sw-swgment-2",
			swSpan: mockGrpcTraceSegment(2),
			dest:   generateTracesOneEmptyResourceSpans(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			swReferencesToSpanLinks(test.swSpan.GetSpans()[0].Refs, test.dest.Links())
			assert.Equal(t, 1, test.dest.Links().Len())
		})
	}
}

func TestSwLogsToSpanEvents(t *testing.T) {
	tests := []struct {
		name   string
		swSpan *agentV3.SegmentObject
		dest   ptrace.Span
	}{
		{
			name:   "mock-sw-swgment-0",
			swSpan: mockGrpcTraceSegment(0),
			dest:   generateTracesOneEmptyResourceSpans(),
		},
		{
			name:   "mock-sw-swgment-1",
			swSpan: mockGrpcTraceSegment(1),
			dest:   generateTracesOneEmptyResourceSpans(),
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seq := strconv.Itoa(index)
			swLogsToSpanEvents(test.swSpan.GetSpans()[0].Logs, test.dest.Events())
			assert.Equal(t, 1, test.dest.Events().Len())
			assert.Equal(t, "logs", test.dest.Events().At(0).Name())
			logValue, _ := test.dest.Events().At(0).Attributes().Get("log-key" + seq)
			assert.Equal(t, "log-value"+seq, logValue.AsString())
		})
	}
}

func TestStringToTraceID(t *testing.T) {
	type args struct {
		traceID string
	}
	tests := []struct {
		name          string
		segmentObject args
		want          [16]byte
	}{
		{
			name:          "mock-sw-normal-trace-id-rfc4122v4",
			segmentObject: args{traceID: "de5980b8-fce3-4a37-aab9-b4ac3af7eedd"},
			want:          [16]byte{222, 89, 128, 184, 252, 227, 74, 55, 170, 185, 180, 172, 58, 247, 238, 221},
		},
		{
			name:          "mock-sw-normal-trace-id-rfc4122",
			segmentObject: args{traceID: "de5980b8fce34a37aab9b4ac3af7eedd"},
			want:          [16]byte{222, 89, 128, 184, 252, 227, 74, 55, 170, 185, 180, 172, 58, 247, 238, 221},
		},
		{
			name:          "mock-sw-trace-id-length-shorter",
			segmentObject: args{traceID: "de59"},
			want:          [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:          "mock-sw-trace-id-length-java-agent",
			segmentObject: args{traceID: "de5980b8fce34a37aab9b4ac3af7eedd.1.16563474296430001"},
			want:          [16]byte{222, 89, 128, 184, 253, 227, 74, 55, 27, 228, 27, 205, 94, 47, 212, 221},
		},
		{
			name:          "mock-sw-trace-id-illegal",
			segmentObject: args{traceID: ".,<>?/-=+MNop"},
			want:          [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := swTraceIDToTraceID(tt.segmentObject.traceID)
			assert.Equal(t, tt.want, got.Bytes())
		})
	}
}

func TestStringToTraceIDUnique(t *testing.T) {
	type args struct {
		traceID string
	}
	tests := []struct {
		name          string
		segmentObject args
	}{
		{
			name:          "mock-sw-trace-id-unique-1",
			segmentObject: args{traceID: "de5980b8fce34a37aab9b4ac3af7eedd.133.16563474296430001"},
		},
		{
			name:          "mock-sw-trace-id-unique-2",
			segmentObject: args{traceID: "de5980b8fce34a37aab9b4ac3af7eedd.133.16534574123430001"},
		},
	}

	var results [2]pcommon.TraceID
	for i := 0; i < 2; i++ {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			got := swTraceIDToTraceID(tt.segmentObject.traceID)
			results[i] = got
		})
	}
	assert.NotEqual(t, tests[0].segmentObject.traceID, t, tests[1].segmentObject.traceID)
	assert.NotEqual(t, results[0], results[1])
}

func TestSegmentIdToSpanId(t *testing.T) {
	type args struct {
		segmentID string
		spanID    uint32
	}
	tests := []struct {
		name string
		args args
		want [8]byte
	}{
		{
			name: "mock-sw-span-id-normal",
			args: args{segmentID: "4f2f27748b8e44ecaf18fe0347194e86.33.16560607369950066", spanID: 123},
			want: [8]byte{233, 196, 85, 168, 37, 66, 48, 106},
		},
		{
			name: "mock-sw-span-id-python-agent",
			args: args{segmentID: "4f2f27748b8e44ecaf18fe0347194e86", spanID: 123},
			want: [8]byte{155, 55, 217, 119, 204, 151, 10, 106},
		},
		{
			name: "mock-sw-span-id-short",
			args: args{segmentID: "16560607369950066", spanID: 12},
			want: [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name: "mock-sw-span-id-illegal-1",
			args: args{segmentID: "1", spanID: 2},
			want: [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name: "mock-sw-span-id-illegal-char",
			args: args{segmentID: ".,<>?/-=+MNop", spanID: 2},
			want: [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := segmentIDToSpanID(tt.args.segmentID, tt.args.spanID)
			assert.Equal(t, tt.want, got.Bytes())
		})
	}
}

func TestSegmentIdToSpanIdUnique(t *testing.T) {
	type args struct {
		segmentID string
		spanID    uint32
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "mock-sw-span-id-unique-1",
			args: args{segmentID: "4f2f27748b8e44ecaf18fe0347194e86.33.16560607369950066", spanID: 123},
		},
		{
			name: "mock-sw-span-id-unique-2",
			args: args{segmentID: "4f2f27748b8e44ecaf18fe0347194e86.33.16560607369950066", spanID: 1},
		},
	}
	var results [2][8]byte
	for i := 0; i < 2; i++ {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			got := segmentIDToSpanID(tt.args.segmentID, tt.args.spanID)
			results[i] = got.Bytes()
		})
	}

	assert.NotEqual(t, results[0], results[1])
}

func generateTracesOneEmptyResourceSpans() ptrace.Span {
	td := ptrace.NewTraces()
	resourceSpan := td.ResourceSpans().AppendEmpty()
	il := resourceSpan.ScopeSpans().AppendEmpty()
	il.Spans().AppendEmpty()
	return il.Spans().At(0)
}

func TestSwTransformIP(t *testing.T) {
	serviceInstanceID := "TestServiceInstanceID@127.0.1.2"
	m := ptrace.NewSpan().Attributes()
	swTransformIP(serviceInstanceID, m)
	v, ok := m.Get(conventions.AttributeNetHostIP)
	assert.True(t, ok)
	assert.Equal(t, v.Type(), pcommon.ValueTypeString)
	assert.Equal(t, v.AsString(), "127.0.1.2")

	m.Clear()
	serviceInstanceID = "TestServiceInstanceID2"
	swTransformIP(serviceInstanceID, m)
	_, ok = m.Get(conventions.AttributeNetHostIP)
	assert.False(t, ok)
}

func mockSwSpanWithAttr(opName string, SpanType agentV3.SpanType, SpanLayer agentV3.SpanLayer) *agentV3.SpanObject {
	// opName: span.OperationName 对于不同的 SpanLayer 级别有不同格式的 opName 格式 HttpLayer：/api/user/list 类型
	// DatabaseLayer：Mysql/mysqlClient/Execute
	span := &agentV3.SpanObject{
		SpanId:        1,
		ParentSpanId:  0,
		StartTime:     time.Now().Unix(),
		EndTime:       time.Now().Unix() + 10,
		OperationName: opName,
		SpanType:      SpanType,
		SpanLayer:     SpanLayer,
		ComponentId:   1,
		IsError:       false,
		SkipAnalysis:  false,
		Tags:          []*common.KeyStringValuePair{},
		Logs:          []*agentV3.Log{},
		Refs:          []*agentV3.SegmentReference{},
	}
	return span
}

func TestSwTagsToAttributesByRule(t *testing.T) {
	t.Run("SpanLayer_Http/SpanType_Entry", func(t *testing.T) {
		dest := pcommon.NewMap()
		opName := "/api/leader/list/"
		dest.InsertString(conventions.AttributeHTTPURL, "https://www.test.com/apitest/user/list")
		swSpan := mockSwSpanWithAttr(opName, agentV3.SpanType_Entry, agentV3.SpanLayer_Http)
		swTagsToAttributesByRule(dest, swSpan)

		v, ok := dest.Get(conventions.AttributeHTTPScheme)
		assert.True(t, ok)
		assert.Equal(t, "https", v.StringVal())

		v, ok = dest.Get(conventions.AttributeHTTPRoute)
		assert.True(t, ok)
		assert.Equal(t, opName, v.StringVal())
	})

	t.Run("SpanLayer_Http/SpanType_Exit", func(t *testing.T) {
		dest := pcommon.NewMap()
		opName := "/api/leader/list/"
		dest.InsertString(conventions.AttributeHTTPURL, "https://www.test.com/apitest/user/list")
		swSpan := mockSwSpanWithAttr(opName, agentV3.SpanType_Exit, agentV3.SpanLayer_Http)
		swTagsToAttributesByRule(dest, swSpan)

		v, ok := dest.Get(conventions.AttributeHTTPTarget)
		assert.True(t, ok)
		assert.Equal(t, "/apitest/user/list", v.StringVal())

		v, ok = dest.Get(conventions.AttributeHTTPHost)
		assert.True(t, ok)
		assert.Equal(t, "www.test.com", v.StringVal())
	})

	t.Run("SpanLayer_RPCFramework", func(t *testing.T) {
		dest := pcommon.NewMap()
		opName := "rpcMethod"
		// SpanLayer_RPCFramework 情况下 SpanType 类型不会影响测试效果
		swSpan := mockSwSpanWithAttr(opName, agentV3.SpanType_Entry, agentV3.SpanLayer_RPCFramework)
		swTagsToAttributesByRule(dest, swSpan)

		v, ok := dest.Get(conventions.AttributeRPCMethod)
		assert.True(t, ok)
		assert.Equal(t, opName, v.StringVal())
	})

	t.Run("SpanLayer_MQ", func(t *testing.T) {
		dest := pcommon.NewMap()
		opName := "messagingTestSystem/TestopName"
		// SpanLayer_MQ 情况下 SpanType 类型不会影响测试效果
		swSpan := mockSwSpanWithAttr(opName, agentV3.SpanType_Entry, agentV3.SpanLayer_MQ)
		swTagsToAttributesByRule(dest, swSpan)

		v, ok := dest.Get(conventions.AttributeMessagingSystem)
		assert.True(t, ok)
		assert.Equal(t, "messagingTestSystem", v.StringVal())
	})

	t.Run("SpanLayer_Database", func(t *testing.T) {
		dest := pcommon.NewMap()
		opName := "Mysql/MysqlClient/execute"
		dbStatement := "SELECT data_id FROM TABLE WHERE XXXX"
		dest.InsertString(conventions.AttributeDBStatement, dbStatement)
		swSpan := mockSwSpanWithAttr(opName, agentV3.SpanType_Entry, agentV3.SpanLayer_Database)
		swTagsToAttributesByRule(dest, swSpan)

		v, ok := dest.Get(conventions.AttributeDBSystem)
		assert.True(t, ok)
		assert.Equal(t, "Mysql", v.StringVal())

		v, ok = dest.Get(conventions.AttributeDBOperation)
		assert.True(t, ok)
		assert.Equal(t, "SELECT", v.StringVal())
	})

	t.Run("SpanLayer_Cache", func(t *testing.T) {
		dest := pcommon.NewMap()
		opName := "Redis/MysqlClient/execute"
		dbStatement := "SET xxx FROM TABLE WHERE XXXX2"
		dest.InsertString(conventions.AttributeDBStatement, dbStatement)
		swSpan := mockSwSpanWithAttr(opName, agentV3.SpanType_Entry, agentV3.SpanLayer_Cache)
		swTagsToAttributesByRule(dest, swSpan)

		v, ok := dest.Get(conventions.AttributeDBSystem)
		assert.True(t, ok)
		assert.Equal(t, "Redis", v.StringVal())

		v, ok = dest.Get(conventions.AttributeDBOperation)
		assert.True(t, ok)
		assert.Equal(t, "SET", v.StringVal())
	})
}
