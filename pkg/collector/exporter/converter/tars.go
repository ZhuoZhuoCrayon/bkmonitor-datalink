// Tencent is pleased to support the open source community by making
// 蓝鲸智云 - 监控平台 (BlueKing - Monitor) available.
// Copyright (C) 2022 THL A29 Limited, a Tencent company. All rights reserved.
// Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://opensource.org/licenses/MIT
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.

package converter

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/elastic/beats/libbeat/common"

	"github.com/TencentBlueKing/bkmonitor-datalink/pkg/collector/define"
	"github.com/TencentBlueKing/bkmonitor-datalink/pkg/collector/internal/utils"
	"github.com/TencentBlueKing/bkmonitor-datalink/pkg/utils/logger"
)

var (
	matchFirstCap = regexp.MustCompile("([a-z0-9])([A-Z])")
	matchAllCap   = regexp.MustCompile("([A-Z]+)([A-Z][a-z])")
)

// CamelToSnake 转换驼峰格式为下划线
func camelToSnake(s string) string {
	// 先替换，比如把 "IDNumber" 替换为 "ID_Number"
	snake := matchAllCap.ReplaceAllString(s, "${1}_${2}")
	// 再替换，例如把 "ID_Number" 替换为 "i_d_number"
	snake = matchFirstCap.ReplaceAllString(snake, "${1}_${2}")
	// 将字符串转换为小写并返回
	return strings.ToLower(snake)
}

// toDistrMap 将分布统计字符串（"0|0,50|1,100|5"）转为结构化数据
func toDistrMap(s string) map[int32]int32 {
	distrMap := make(map[int32]int32)
	pairs := strings.Split(s, ",")
	for _, pair := range pairs {
		// 按竖线分割每个键值对
		p := strings.Split(pair, "|")
		if len(p) != 2 {
			continue
		}
		val, err := strconv.Atoi(p[0])
		if err != nil {
			continue
		}
		count, err := strconv.Atoi(p[1])
		if err != nil {
			continue
		}
		distrMap[int32(val)] = int32(count)
	}
	return distrMap
}

// toHistogram 根据分布情况，生成统计指标
func toHistogram(name string, target string, timestamp int64, distrMap map[int32]int32, dims map[string]string, isDurant bool) []*promMapper {
	count := 0
	pms := make([]*promMapper, 0)
	distrList := make([]int, 0, len(distrMap))
	for distr := range distrMap {
		distrList = append(distrList, int(distr))
	}
	sort.Ints(distrList)

	for distr := range distrList {
		cnt, _ := distrMap[int32(distr)]
		count += int(cnt)
		dims := utils.CloneMap(dims)
		if isDurant {
			dims["le"] = strconv.FormatFloat(float64(distr)/1000, 'f', -1, 64)
		} else {
			dims["le"] = strconv.Itoa(distr)
		}
		pm := &promMapper{
			Metrics:    common.MapStr{name + "_bucket": count},
			Target:     target,
			Timestamp:  timestamp,
			Dimensions: dims,
		}
		pms = append(pms, pm)
	}

	pms = append(pms, &promMapper{
		Metrics:    common.MapStr{name + "_count": count},
		Target:     target,
		Timestamp:  timestamp,
		Dimensions: utils.CloneMap(dims),
	})

	pms = append(pms, &promMapper{
		Metrics:   common.MapStr{name + "_bucket": count},
		Target:    target,
		Timestamp: timestamp,
		Dimensions: utils.MergeMaps(
			utils.CloneMap(dims),
			map[string]string{"le": strconv.FormatFloat(math.Inf(+1), 'f', -1, 64)},
		),
	})

	return pms
}

// TarsEvent is a struct that embeds CommonEvent.
type TarsEvent struct {
	define.CommonEvent
}

// RecordType returns the type of record.
func (e TarsEvent) RecordType() define.RecordType {
	return define.RecordTars
}

var TarsConverter EventConverter = tarsConverter{}

type tarsConverter struct{}

func (c tarsConverter) ToEvent(token define.Token, dataId int32, data common.MapStr) define.Event {
	return TarsEvent{define.NewCommonEvent(token, dataId, data)}
}

func (c tarsConverter) ToDataID(record *define.Record) int32 {
	return record.Token.MetricsDataId
}

func (c tarsConverter) Convert(record *define.Record, f define.GatherFunc) {
	var events []define.Event
	dataID := c.ToDataID(record)
	data := record.Data.(*define.TarsData)
	if data.Type == define.TarsPropertyType {
		events = c.handleProp(record.Token, dataID, record.RequestClient.IP, data)
	} else {
		events = c.handleStat(record.Token, dataID, record.RequestClient.IP, data)
	}
	if len(events) > 0 {
		f(events...)
	}
}

// handleStat 处理服务统计指标
func (c tarsConverter) handleStat(token define.Token, dataID int32, ip string, data *define.TarsData) []define.Event {
	var events []define.Event
	stats := data.Data.(*define.TarsStatData).Stats
	for head, body := range stats {
		masterName, _ := define.TokenFromString(head.MasterName)
		slaveName, _ := define.TokenFromString(head.SlaveName)
		dims := map[string]string{
			"master_name":    masterName,
			"slave_name":     slaveName,
			"interface_name": head.InterfaceName,
			"master_ip":      head.MasterIp,
			"slave_ip":       head.SlaveIp,
			"slave_port":     strconv.Itoa(int(head.SlavePort)),
			"return_value":   strconv.Itoa(int(head.ReturnValue)),
			"slave_set_name": head.SlaveSetName,
			"slave_set_area": head.SlaveSetArea,
			"slave_set_id":   head.SlaveSetID,
			"tars_version":   head.TarsVersion,
		}
		pm := &promMapper{
			Metrics: common.MapStr{
				"tars_timeout_total":                body.TimeoutCount,
				"tars_requests_total":               body.Count,
				"tars_exceptions_total":             body.ExecCount,
				"tars_request_duration_seconds_max": float64(body.MaxRspTime) / 1000,
				"tars_request_duration_seconds_min": float64(body.MinRspTime) / 1000,
				"tars_request_duration_seconds_sum": float64(body.TotalRspTime) / 1000,
			},
			Target:     head.MasterIp,
			Timestamp:  data.Timestamp,
			Dimensions: utils.CloneMap(dims),
		}
		pms := toHistogram("tars_request_duration_seconds", head.MasterIp, data.Timestamp, body.IntervalCount, dims, true)
		pms = append(pms, pm)
		for _, pm := range pms {
			events = append(events, c.ToEvent(token, dataID, pm.AsMapStr()))
		}
	}
	return events
}

// handleStat 处理业务特性指标
func (c tarsConverter) handleProp(token define.Token, dataID int32, ip string, data *define.TarsData) []define.Event {
	events := make([]define.Event, 0)
	props := data.Data.(*define.TarsPropertyData).Props
	for head, body := range props {
		propertyName := camelToSnake(head.PropertyName)
		moduleName, _ := define.TokenFromString(head.ModuleName)
		dims := map[string]string{
			"ip":             head.Ip,
			"module_name":    moduleName,
			"property_name":  head.PropertyName,
			"set_name":       head.SetName,
			"set_area":       head.SetArea,
			"s_container":    head.SContainer,
			"i_property_ver": strconv.Itoa(int(head.IPropertyVer)),
		}

		metrics := common.MapStr{}
		for _, info := range body.VInfo {
			switch info.Policy {
			case "Distr":
				distrMap := toDistrMap(info.Value)
				metricName := propertyName + "_distr"
				if len(distrMap) == 0 {
					logger.Warnf("[handleProp] empty distrMap, Distr=%s", distrMap)
					continue
				}
				pms := toHistogram(metricName, head.Ip, data.Timestamp, distrMap, dims, false)
				for _, pm := range pms {
					events = append(events, c.ToEvent(token, dataID, pm.AsMapStr()))
				}
			default:
				metricName := fmt.Sprintf("%s_%s", propertyName, strings.ToLower(info.Policy))
				val, err := strconv.ParseFloat(info.Value, 64)
				if err != nil {
					DefaultMetricMonitor.IncConverterFailedCounter(define.RecordTars, dataID)
					continue
				}
				metrics[metricName] = val
			}
		}
		if len(metrics) != 0 {
			pm := promMapper{
				Metrics:    metrics,
				Target:     head.Ip,
				Timestamp:  data.Timestamp,
				Dimensions: utils.CloneMap(dims),
			}
			events = append(events, c.ToEvent(token, dataID, pm.AsMapStr()))
		}
	}
	return events
}
