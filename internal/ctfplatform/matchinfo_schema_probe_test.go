package ctfplatform

// ───────────────────────── match_info 字段 schema 探针（2026-11-10）─────────────────────────
//
// 存在理由（时间窗驱动策略·第一轮，用户拍板）：`GetMatchInfo` 已接线但只打日志，
// 要升级为「用比赛时间窗自动推导首血窗口/停跑时机」，必须先拿到**双平台真实字段清单**
// ——评估文档明记该风险："返回是 map[string]interface{} 无 schema 锁定，
// DASCTF 与 CTF² 字段名不保证一致"。本探针就是取证工具：持凭证即打印全量 key/value
// 与 JSON 原文，无凭证 CI 永绿（与既有 live smoke 同纪律：不伪造）。
//
// 用法（服务器 172.16.222.99，runner 环境已配凭证时）：
//   go test -count=1 -run "LiveMatchInfoSchemaProbe" -v ./internal/ctfplatform/ 2>&1 | grep -A40 "排序 key"
//
// 第二轮（推导逻辑实施）的输入 = 本探针在两个平台上的真实输出，勿凭记忆实现。

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"testing"
	"time"

	"go.uber.org/zap"
)

func dumpMapKeys(t *testing.T, label string, m map[string]interface{}) {
	t.Helper()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Logf("%s 排序 key 清单（%d 个）：%v", label, len(keys), keys)
	if b, err := json.Marshal(m); err == nil {
		t.Logf("%s 全字段 JSON 原文：%s", label, string(b))
	}
}

// TestCTF2LiveMatchInfoSchemaProbe CTF² 竞技场 match_info + scoreboard 全字段导出。
// 门控：CTF2_BASE_URL 与 CTF2_AGENT_TOKEN 同时存在才跑，否则 Skip（不伪造）。
func TestCTF2LiveMatchInfoSchemaProbe(t *testing.T) {
	baseURL := os.Getenv("CTF2_BASE_URL")
	token := os.Getenv("CTF2_AGENT_TOKEN")
	if baseURL == "" || token == "" {
		t.Skip("跳过 CTF² match_info 探针：未设置 CTF2_BASE_URL / CTF2_AGENT_TOKEN（按纪律不伪造绿）")
	}
	compID := os.Getenv("CTF2_COMPETITION_ID")
	if compID == "" {
		compID = "1"
	}
	p := NewCTF2Platform(baseURL, token, zap.NewNop())
	p.CompetitionID = compID
	p.HTTPClient = &http.Client{Timeout: 30 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	mi, err := p.GetMatchInfo(ctx)
	if err != nil {
		t.Logf("⚠️ CTF² GetMatchInfo 返回错误（网络/凭证态，非代码缺陷）: %v", err)
		return
	}
	dumpMapKeys(t, "CTF² match_info", mi)

	ov, err := p.GetOverview(ctx)
	if err != nil {
		t.Logf("⚠️ CTF² GetOverview 返回错误（网络/凭证态）: %v", err)
		return
	}
	dumpMapKeys(t, "CTF² overview(scoreboard)", ov)
}

// TestDASCTFLiveMatchInfoSchemaProbe DASCTF match_info + overview 全字段导出。
// 门控：DASCTF_BASE_URL 与 DASCTF_TOKEN 同时存在才跑，否则 Skip。
func TestDASCTFLiveMatchInfoSchemaProbe(t *testing.T) {
	baseURL := os.Getenv("DASCTF_BASE_URL")
	token := os.Getenv("DASCTF_TOKEN")
	if baseURL == "" || token == "" {
		t.Skip("跳过 DASCTF match_info 探针：未设置 DASCTF_BASE_URL / DASCTF_TOKEN（按纪律不伪造绿）")
	}
	p := NewDasCTFPlatform(baseURL, token, zap.NewNop())

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	mi, err := p.GetMatchInfo(ctx)
	if err != nil {
		t.Logf("⚠️ DASCTF GetMatchInfo 返回错误（网络/凭证态，非代码缺陷）: %v", err)
		return
	}
	dumpMapKeys(t, "DASCTF match_info", mi)

	ov, err := p.GetOverview(ctx)
	if err != nil {
		t.Logf("⚠️ DASCTF GetOverview 返回错误（网络/凭证态）: %v", err)
		return
	}
	dumpMapKeys(t, "DASCTF overview", ov)
}
