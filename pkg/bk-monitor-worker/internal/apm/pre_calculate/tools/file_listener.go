// Tencent is pleased to support the open source community by making
// 蓝鲸智云 - 监控平台 (BlueKing - Monitor) available.
// Copyright (C) 2022 THL A29 Limited, a Tencent company. All rights reserved.
// Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://opensource.org/licenses/MIT
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.

package tools

import (
	"context"

	"github.com/TencentBlueKing/bkmonitor-datalink/pkg/bk-monitor-worker/internal/apm/pre_calculate"
	"github.com/TencentBlueKing/bkmonitor-datalink/pkg/bk-monitor-worker/internal/apm/pre_calculate/core"
)

func StartListenerFromFile(ctx context.Context, filePath string) error {
	processor, err := pre_calculate.Initial(ctx)
	if err != nil {
		return err
	}
	if err := core.CreateMockMetadataCenter(); err != nil {
		return err
	}

	processor.RunWithStandLone(filePath)
	return nil
}