//go:build !race

package sysstat

// raceEnabled 是否在 -race 构建下。见 race_on.go 的说明。
const raceEnabled = false
