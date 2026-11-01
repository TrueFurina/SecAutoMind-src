package pyskill

import (
	"testing"
	"time"
)

// L2 预算是"赛时不会自杀"的唯一保险。2026-11-01 实测：crypto 类 28 个 skill、
// 单 skill 最多 6 个(文件×分派)变体、每次子进程 30s，无限预算下最坏 56 分钟/题；
// 而 mhk2 一道题就试了 104s。这些用例锁住"环境变量能真正改到预算"这条链路，
// 避免以后把 L2BudgetFromEnv 写成读死值、或把 0/非法值当成"不限"。
func TestL2BudgetFromEnv(t *testing.T) {
	def := 180 * time.Second
	cases := []struct {
		name string
		env  string
		want time.Duration
	}{
		{"未设置→兜底", "", def},
		{"正常覆盖", "90s", 90 * time.Second},
		{"分钟形态", "5m", 5 * time.Minute},
		{"0 视为未设置（不允许靠 0 变成不限）", "0s", def},
		{"非法值→兜底", "abc", def},
		{"负数→兜底", "-30s", def},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("CTF_L2_BUDGET", c.env) // 空串 = 未设置（osGetenv 走 LookupEnv + TrimSpace）
			if got := L2BudgetFromEnv(def); got != c.want {
				t.Fatalf("CTF_L2_BUDGET=%q 应得 %v，实际 %v", c.env, c.want, got)
			}
		})
	}
}
