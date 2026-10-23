// presolve_python_test.go — 西湖论剑 Python 兜底通道测试（2026-10-23 吞并接入）
package ctfplatform

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

const (
	testXHLJLegacy = `E:\Program\SecAutoMind\data\ctf_benchmark\xhlj_legacy`
	testPyVenv     = `C:/Users/Lenovo/.workbuddy/binaries/python/envs/default/Scripts/python.exe`
)

// skipNoPython：python 或 legacy 资产缺失时 SKIP（不伪造绿，AGENTS.md 诚实口径）。
func skipNoPython(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(testPyVenv); err != nil {
		t.Skipf("测试 python 环境缺失: %v", err)
	}
	if _, err := os.Stat(filepath.Join(testXHLJLegacy, "runner.py")); err != nil {
		t.Skipf("西湖论剑迁移资产缺失: %v", err)
	}
}

func TestPythonLegacyFallbackVigenere(t *testing.T) {
	skipNoPython(t)
	t.Setenv(envPythonBin, testPyVenv)
	t.Setenv(envXHLJLegacyDir, testXHLJLegacy)
	t.Setenv(envPythonFallbackTimout, "60000")

	// 构造 Vigenère 加密文本（key=KEY，data 为密文，skill 从 text 提取 key/data）
	text := "key: KEY data: NEQMXD{diqd_jjkk_123}"
	flags := tryPythonLegacyFallback(text, nil)
	if len(flags) == 0 {
		t.Fatalf("xhlj_python 兜底未命中 vigenere 用例（text=%q）", text)
	}
	found := false
	for _, f := range flags {
		if f == "DASCTF{test_flag_123}" {
			found = true
		}
	}
	if !found {
		t.Fatalf("未解出期望明文，实际候选: %v", flags)
	}
}

func TestPythonLegacyFallbackDisabled(t *testing.T) {
	t.Setenv(envPythonFallback, "0")
	if flags := tryPythonLegacyFallback("key: KEY data: NEQMXD{diqd_jjkk_123}", nil); flags != nil {
		t.Fatalf("开关关闭时不应命中，实际: %v", flags)
	}
}

func TestPythonLegacyFallbackEmpty(t *testing.T) {
	t.Setenv(envPythonFallback, "1")
	if flags := tryPythonLegacyFallback("   ", nil); flags != nil {
		t.Fatalf("空文本不应命中，实际: %v", flags)
	}
}

func TestPythonLegacyFallbackNoMatch(t *testing.T) {
	skipNoPython(t)
	t.Setenv(envPythonBin, testPyVenv)
	t.Setenv(envXHLJLegacyDir, testXHLJLegacy)
	t.Setenv(envPythonFallbackTimout, "60000")

	// 普通英文文本：79 个 skill 全跑后不应产生 flag 形态误报（fail-closed 不谎报）
	plain := "This is just a normal English sentence without any hidden flag inside it."
	flags := tryPythonLegacyFallback(plain, nil)
	if len(flags) != 0 {
		t.Fatalf("普通文本不应命中，实际候选: %v", flags)
	}
}

func TestPythonLegacyFallbackThroughRegistry(t *testing.T) {
	skipNoPython(t)
	t.Setenv(envPythonBin, testPyVenv)
	t.Setenv(envXHLJLegacyDir, testXHLJLegacy)
	t.Setenv(envPythonFallbackTimout, "60000")

	pr := NewPresolver(zap.NewNop())
	ch := &Challenge{
		ID:          "test_xhlj_vigenere",
		Category:    "crypto",
		Description: "key: KEY data: NEQMXD{diqd_jjkk_123}",
	}
	res := pr.PresolveWithRegistry(context.Background(), ch, nil)
	if res == nil || !res.Solved {
		t.Fatalf("PresolveWithRegistry 应解出用例，实际: %+v", res)
	}
	// 端到端断言：无论 Go 求解器还是 xhlj_python 兜底命中，候选必须含期望明文。
	// （Go 求解器优先于 Python 兜底是设计意图：registry sweep 在 xhlj_python 之前。）
	found := false
	for _, f := range res.Flags {
		if f == "DASCTF{test_flag_123}" {
			found = true
		}
	}
	if !found {
		t.Fatalf("未解出期望明文，引擎=%s 候选=%v", res.Engine, res.Flags)
	}
}
