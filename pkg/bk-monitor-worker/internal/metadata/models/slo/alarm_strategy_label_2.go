// Code generated by gorm.io/gen. DO NOT EDIT.
// Code generated by gorm.io/gen. DO NOT EDIT.
// Code generated by gorm.io/gen. DO NOT EDIT.

package slo

const TableNameAlarmStrategyLabel = "alarm_strategy_label"

//go:generate goqueryset -in alarm_strategy_label.go -out qs_alarm_strategy_label_gen.go

// AlarmStrategyLabel mapped from table <alarm_strategy_label>
// gen:qs
type AlarmStrategyLabel struct {
	ID         int32  `gorm:"column:id;primaryKey;autoIncrement:true" json:"id"`
	LabelName  string `gorm:"column:label_name;not null" json:"label_name"`
	BkBizID    int32  `gorm:"column:bk_biz_id;not null" json:"bk_biz_id"`
	StrategyID int32  `gorm:"column:strategy_id;not null" json:"strategy_id"`
}

// TableName AlarmStrategyLabel's table name
func (*AlarmStrategyLabel) TableName() string {
	return TableNameAlarmStrategyLabel
}