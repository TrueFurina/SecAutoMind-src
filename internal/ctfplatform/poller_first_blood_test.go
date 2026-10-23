package ctfplatform

// poller_first_blood_test.go —— 首血扫描模式的确定性测试（纯函数，不依赖墙钟）。

import (
	"testing"
	"time"
)

func TestPollWaitFirstBlood(t *testing.T) {
	base := 30 * time.Second
	cases := []struct {
		name    string
		cfg     PollerConfig
		elapsed time.Duration
		want    time.Duration
	}{
		{
			name:    "默认关闭（零值）→ 始终基础间隔",
			cfg:     PollerConfig{PollInterval: base},
			elapsed: 0,
			want:    base,
		},
		{
			name:    "窗口内 → 短间隔",
			cfg:     PollerConfig{PollInterval: base, FirstBloodWindow: 10 * time.Minute, FirstBloodInterval: 5 * time.Second},
			elapsed: 2 * time.Minute,
			want:    5 * time.Second,
		},
		{
			name:    "窗口边界（恰好等于 window）→ 已回落",
			cfg:     PollerConfig{PollInterval: base, FirstBloodWindow: 10 * time.Minute, FirstBloodInterval: 5 * time.Second},
			elapsed: 10 * time.Minute,
			want:    base,
		},
		{
			name:    "窗口过后 → 基础间隔",
			cfg:     PollerConfig{PollInterval: base, FirstBloodWindow: 10 * time.Minute, FirstBloodInterval: 5 * time.Second},
			elapsed: 11 * time.Minute,
			want:    base,
		},
		{
			name:    "interval ≥ base（语义倒挂）→ 按关闭处理",
			cfg:     PollerConfig{PollInterval: base, FirstBloodWindow: 10 * time.Minute, FirstBloodInterval: 30 * time.Second},
			elapsed: time.Minute,
			want:    base,
		},
		{
			name:    "只给 window 不给 interval → 按关闭处理",
			cfg:     PollerConfig{PollInterval: base, FirstBloodWindow: 10 * time.Minute},
			elapsed: time.Minute,
			want:    base,
		},
		{
			name:    "负 window → 按关闭处理",
			cfg:     PollerConfig{PollInterval: base, FirstBloodWindow: -time.Minute, FirstBloodInterval: 5 * time.Second},
			elapsed: 0,
			want:    base,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pollWait(tc.cfg, tc.elapsed); got != tc.want {
				t.Fatalf("pollWait=%v，期望 %v", got, tc.want)
			}
		})
	}
}

func TestFirstBloodActive(t *testing.T) {
	base := 30 * time.Second
	active := PollerConfig{PollInterval: base, FirstBloodWindow: 10 * time.Minute, FirstBloodInterval: 5 * time.Second}
	if !firstBloodActive(active) {
		t.Fatal("合法配置应判定为激活")
	}
	for name, cfg := range map[string]PollerConfig{
		"零值关闭":      {PollInterval: base},
		"窗口为 0":     {PollInterval: base, FirstBloodInterval: 5 * time.Second},
		"间隔为 0":     {PollInterval: base, FirstBloodWindow: time.Minute},
		"间隔不小于基础间隔": {PollInterval: base, FirstBloodWindow: time.Minute, FirstBloodInterval: base},
		"负窗口":       {PollInterval: base, FirstBloodWindow: -time.Minute, FirstBloodInterval: 5 * time.Second},
	} {
		if firstBloodActive(cfg) {
			t.Fatalf("%s：不应判定为激活", name)
		}
	}
}

func TestDefaultPollerConfigFirstBloodDisabled(t *testing.T) {
	cfg := DefaultPollerConfig()
	if cfg.FirstBloodWindow != 0 || cfg.FirstBloodInterval != 0 {
		t.Fatalf("默认配置必须关闭首血扫描，得到 window=%v interval=%v",
			cfg.FirstBloodWindow, cfg.FirstBloodInterval)
	}
	if firstBloodActive(cfg) {
		t.Fatal("默认配置不得激活首血扫描")
	}
}
