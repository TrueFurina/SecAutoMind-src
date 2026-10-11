package handler

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

const testRiskPolicyYAML = `policy_version: 1
default_risk: medium
default_hitl: true
tools:
  - name: sqlmap
    risk: high
    hitl: true
    category: scanner
    reason: "r1"
  - name: fofa_search
    risk: medium
    hitl: false
    category: recon
    reason: "r2"
  - name: query-execution-result
    risk: high
    hitl: true
    category: agent-native
    reason: "r3"
`

// enableHITLForTest 直接为测试会话写入一条已开启的运行时配置。
func enableHITLForTest(m *HITLManager, conv string) {
	m.mu.Lock()
	m.runtime[conv] = hitlRuntimeConfig{
		Enabled:        true,
		SensitiveTools: map[string]struct{}{},
	}
	m.mu.Unlock()
}

func TestLoadRiskPolicyPopulatesByName(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "risk_policy.yaml"), []byte(testRiskPolicyYAML), 0644); err != nil {
		t.Fatal(err)
	}
	m := NewHITLManager(nil, zap.NewNop())
	if err := m.LoadRiskPolicy(dir); err != nil {
		t.Fatalf("LoadRiskPolicy 失败: %v", err)
	}
	if m.riskPolicy == nil {
		t.Fatal("riskPolicy 未加载")
	}
	if m.riskPolicy.byName["sqlmap"] != true {
		t.Errorf("sqlmap 期望 hitl=true")
	}
	if m.riskPolicy.byName["fofa_search"] != false {
		t.Errorf("fofa_search 期望 hitl=false")
	}
	if m.riskPolicy.byName["query-execution-result"] != true {
		t.Errorf("query-execution-result 期望 hitl=true（连字符键）")
	}
	if m.riskPolicy.DefaultHITL != true {
		t.Errorf("default_hitl 期望 true")
	}
	if len(m.riskPolicy.byName) != 3 {
		t.Errorf("byName 期望 3 条，实际 %d", len(m.riskPolicy.byName))
	}
}

func TestShouldInterruptUsesRiskPolicy(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "risk_policy.yaml"), []byte(testRiskPolicyYAML), 0644); err != nil {
		t.Fatal(err)
	}
	m := NewHITLManager(nil, zap.NewNop())
	if err := m.LoadRiskPolicy(dir); err != nil {
		t.Fatal(err)
	}
	conv := "conv-policy"
	enableHITLForTest(m, conv)

	// 已知工具：以策略命中为准
	_, needSqlmap := m.shouldInterrupt(conv, "sqlmap")
	if !needSqlmap {
		t.Errorf("sqlmap 应要求 HITL")
	}
	_, needFofa := m.shouldInterrupt(conv, "fofa_search")
	if needFofa {
		t.Errorf("fofa_search 不应要求 HITL")
	}
	// 连字符键也匹配
	_, needQuery := m.shouldInterrupt(conv, "query-execution-result")
	if !needQuery {
		t.Errorf("query-execution-result 应要求 HITL")
	}
	// 大小写不敏感
	_, needUpper := m.shouldInterrupt(conv, "SQLMAP")
	if !needUpper {
		t.Errorf("SQLMAP（大写）应要求 HITL")
	}
}

func TestShouldInterruptPolicyUnknownFallsBackToWhitelist(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "risk_policy.yaml"), []byte(testRiskPolicyYAML), 0644); err != nil {
		t.Fatal(err)
	}
	m := NewHITLManager(nil, zap.NewNop())
	if err := m.LoadRiskPolicy(dir); err != nil {
		t.Fatal(err)
	}
	conv := "conv-unknown"
	// 启用 HITL，空白名单 => 默认全拦截
	enableHITLForTest(m, conv)

	// 未在策略登记的工具：回退到会话级白名单逻辑（空白名单 => 拦截）
	_, needUnknown := m.shouldInterrupt(conv, "totally_unknown_tool")
	if !needUnknown {
		t.Errorf("未登记工具在空白名单下应被拦截（回退默认）")
	}

	// 会话级白名单豁免：未登记工具在白名单内 => 放行
	m.mu.Lock()
	m.runtime[conv] = hitlRuntimeConfig{
		Enabled:        true,
		SensitiveTools: map[string]struct{}{"totally_unknown_tool": {}},
	}
	m.mu.Unlock()
	_, needUnknownWhitelisted := m.shouldInterrupt(conv, "totally_unknown_tool")
	if needUnknownWhitelisted {
		t.Errorf("未登记工具在会话白名单内应放行（策略未命中回退白名单）")
	}
}

func TestShouldInterruptNoPolicyFallsBackToWhitelist(t *testing.T) {
	m := NewHITLManager(nil, zap.NewNop())
	conv := "conv-nopolicy"
	enableHITLForTest(m, conv)
	// 无策略 => 启用 HITL 且空白名单 => 全拦截（既有行为不变）
	_, need := m.shouldInterrupt(conv, "anything")
	if !need {
		t.Errorf("无策略时启用 HITL 应拦截全部工具")
	}
}

func TestLoadRiskPolicyMissingFileIsNoop(t *testing.T) {
	m := NewHITLManager(nil, zap.NewNop())
	// 不存在的目录：应安全跳过，不返回错误
	if err := m.LoadRiskPolicy(filepath.Join(t.TempDir(), "nope")); err != nil {
		t.Errorf("缺失 risk_policy.yaml 不应返回错误: %v", err)
	}
	if m.riskPolicy != nil {
		t.Errorf("缺失文件时 riskPolicy 应保持 nil")
	}
}

// TestMaybeReloadRiskPolicy 验证：risk_policy.yaml 在进程运行期被修改后，
// maybeReloadRiskPolicy 能原子热重载策略，且 mtime 未变化时不重载。
func TestMaybeReloadRiskPolicy(t *testing.T) {
	dir := t.TempDir()
	initYAML := `policy_version: 1
default_risk: medium
default_hitl: true
tools:
  - name: sqlmap
    risk: high
    hitl: true
    category: scanner
    reason: "r1"
  - name: fofa_search
    risk: medium
    hitl: false
    category: recon
    reason: "r2"
`
	if err := os.WriteFile(filepath.Join(dir, "risk_policy.yaml"), []byte(initYAML), 0644); err != nil {
		t.Fatal(err)
	}
	m := NewHITLManager(nil, zap.NewNop())
	if err := m.LoadRiskPolicy(dir); err != nil {
		t.Fatal(err)
	}
	if m.riskPolicy == nil || m.riskPolicy.byName["sqlmap"] != true {
		t.Fatal("初始加载失败")
	}

	// 1) 内容变了但 mtime 回拨到旧时间 => 不应重载（保留旧策略）
	unchanged := `policy_version: 1
default_risk: medium
default_hitl: true
tools:
  - name: sqlmap
    risk: high
    hitl: false
    category: scanner
    reason: "r1"
  - name: fofa_search
    risk: medium
    hitl: false
    category: recon
    reason: "r2"
`
	if err := os.WriteFile(filepath.Join(dir, "risk_policy.yaml"), []byte(unchanged), 0644); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "risk_policy.yaml")); err == nil {
		old := fi.ModTime().Add(-time.Hour)
		os.Chtimes(filepath.Join(dir, "risk_policy.yaml"), old, old)
	}
	m.maybeReloadRiskPolicy()
	if m.riskPolicy.byName["sqlmap"] != true {
		t.Errorf("mtime 未变时不应重载，sqlmap 应仍为 hitl=true")
	}

	// 2) 内容变且 mtime 变（WriteFile 默认当前时间晚于旧记录） => 热重载生效
	changed := `policy_version: 1
default_risk: medium
default_hitl: true
tools:
  - name: sqlmap
    risk: high
    hitl: false
    category: scanner
    reason: "r1"
  - name: fofa_search
    risk: medium
    hitl: false
    category: recon
    reason: "r2"
`
	if err := os.WriteFile(filepath.Join(dir, "risk_policy.yaml"), []byte(changed), 0644); err != nil {
		t.Fatal(err)
	}
	m.maybeReloadRiskPolicy()
	if m.riskPolicy.byName["sqlmap"] != false {
		t.Errorf("mtime 变化后应热重载，sqlmap 应为 hitl=false")
	}
}
