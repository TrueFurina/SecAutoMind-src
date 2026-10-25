package ctfplatform

// poller_config_validate_test.go —— PollerConfig 各开关语义倒挂/危险值校验
// （听风第五刀配套）。覆盖 ValidatePollerConfig 的全部分支：
// 默认配置零告警零错误、三类致命倒挂 fail-closed、非致命项修正、首血倒挂/合法。

import (
	"testing"
	"time"
)

func TestValidatePollerConfigDefaultOK(t *testing.T) {
	_, warns, err := ValidatePollerConfig(DefaultPollerConfig())
	if err != nil {
		t.Fatalf("默认配置应通过校验: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("默认配置应零告警，实际: %v", warns)
	}
}

func TestValidatePollerConfigMaxConcurrencyZeroFatal(t *testing.T) {
	cfg := DefaultPollerConfig()
	cfg.MaxConcurrency = 0
	_, _, err := ValidatePollerConfig(cfg)
	if err == nil {
		t.Fatal("max_concurrency=0 应致命失败（死锁）")
	}
}

func TestValidatePollerConfigPollIntervalZeroFatal(t *testing.T) {
	cfg := DefaultPollerConfig()
	cfg.PollInterval = 0
	_, _, err := ValidatePollerConfig(cfg)
	if err == nil {
		t.Fatal("poll_interval=0 应致命失败（空转忙循环）")
	}
}

func TestValidatePollerConfigSolveTimeoutZeroFatal(t *testing.T) {
	cfg := DefaultPollerConfig()
	cfg.SolveTimeout = 0
	_, _, err := ValidatePollerConfig(cfg)
	if err == nil {
		t.Fatal("solve_timeout=0 应致命失败（零题可解）")
	}
}

func TestValidatePollerConfigNegativeRetrySubmitFixed(t *testing.T) {
	cfg := DefaultPollerConfig()
	cfg.MaxRetrySubmit = -1
	fixed, warns, err := ValidatePollerConfig(cfg)
	if err != nil {
		t.Fatalf("负重试次数应可修正不致命: %v", err)
	}
	if fixed.MaxRetrySubmit != 0 {
		t.Fatalf("应修正为 0，实际 %d", fixed.MaxRetrySubmit)
	}
	if len(warns) == 0 {
		t.Fatal("应产生告警")
	}
}

func TestValidatePollerConfigFirstBloodInvertedWarn(t *testing.T) {
	cfg := DefaultPollerConfig()
	cfg.FirstBloodWindow = 60 * time.Second
	cfg.FirstBloodInterval = 40 * time.Second // > PollInterval(30s) → 倒挂
	fixed, warns, err := ValidatePollerConfig(cfg)
	if err != nil {
		t.Fatalf("首血倒挂应非致命: %v", err)
	}
	if fixed.FirstBloodWindow != 0 || fixed.FirstBloodInterval != 0 {
		t.Fatalf("首血倒挂应被关闭，实际 window=%v interval=%v", fixed.FirstBloodWindow, fixed.FirstBloodInterval)
	}
	if len(warns) == 0 {
		t.Fatal("首血倒挂应告警")
	}
}

func TestValidatePollerConfigFirstBloodValidNoWarn(t *testing.T) {
	cfg := DefaultPollerConfig()
	cfg.FirstBloodWindow = 60 * time.Second
	cfg.FirstBloodInterval = 10 * time.Second // < PollInterval(30s) → 合法
	fixed, warns, err := ValidatePollerConfig(cfg)
	if err != nil {
		t.Fatalf("合法首血应无错误: %v", err)
	}
	if fixed.FirstBloodWindow != 60*time.Second || fixed.FirstBloodInterval != 10*time.Second {
		t.Fatalf("合法首血不应被改，实际 window=%v interval=%v", fixed.FirstBloodWindow, fixed.FirstBloodInterval)
	}
	if len(warns) != 0 {
		t.Fatalf("合法首血应零告警，实际: %v", warns)
	}
}
