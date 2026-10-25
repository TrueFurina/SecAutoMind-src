// pyskill_rich_test.go —— P0-1 RunSkillRich 端到端回归（2026-10-25）。
//
// 锁死的不变量：
//   A. RunSkillRich 经真实子进程契约（import skill → run(params) → print JSON）
//      能跑通 ctf_sage 适配层 → scripts/ctf_sage 模板库全链，数学参数（extra）
//      直达 solve 函数——这是 L3「模板优先」的机器可验证判据；
//   B. 前提不满足走结构化 not_applicable（不是崩、不是假 solved）；
//   C. 参数错误也是结构化 note（不崩）；
//   D. extra 优先级高于 description 正则提取值（数学参数不许被猜的值覆盖）。
//
// 环境缺 python 时 SKIP（CI 无常驻 python；本机/服务器都有）。
package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"secautomind-ai/internal/ctfplatform"
)

// resolveTestPython 复刻 newPySkillRunner 的解析序；找不到返回 ""（调用方 SKIP）。
func resolveTestPython() string {
	for _, c := range []string{"python3", "python", `C:\Users\Lenovo\.workbuddy\binaries\python\envs\default\Scripts\python.exe`} {
		if _, err := exec.LookPath(c); err == nil {
			return c
		}
	}
	return ""
}

// repoSkillsDir 返回技能目录（go test 的 cwd = cmd/runner/，仓库根上溯两级）。
func repoSkillsDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("解析仓库根失败: %v", err)
	}
	dir := filepath.Join(root, "CTF-Agent_融合", "ctf_agent", "skills")
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		t.Skipf("技能目录不存在: %s", dir)
	}
	return dir
}

func newRichTestRunner(t *testing.T) *pySkillRunner {
	t.Helper()
	py := resolveTestPython()
	if py == "" {
		t.Skip("无可用 python（python3/python/workbuddy venv 均不在）")
	}
	return &pySkillRunner{
		pythonPath: py,
		skillsDir:  repoSkillsDir(t),
		timeout:    60 * time.Second,
		logger:     zap.NewNop(),
	}
}

// A. 端到端：ctf_sage_t1_coppersmith 适配层 + 模板库恢复 Sage docstring 实例的根 4。
func TestRunSkillRichEndToEndCoppersmith(t *testing.T) {
	r := newRichTestRunner(t)
	ch := &ctfplatform.Challenge{Title: "e2e", Category: "crypto", Description: "无描述"}
	out, ok := r.RunSkillRich(context.Background(), "ctf_sage_t1_coppersmith", ch, map[string]any{
		"modulus": 10001,
		"poly":    []any{9779, 5000, 10, 1}, // x^3 + 10x^2 + 5000x - 222 mod 10001 → 根 4
	})
	if !ok {
		t.Fatalf("RunSkillRich 失败（子进程链没跑通）: %s", out)
	}
	if !strings.Contains(out, `"ok": true`) && !strings.Contains(out, `"ok":true`) {
		t.Fatalf("模板未报 solved: %s", out)
	}
	if !strings.Contains(out, "4") {
		t.Fatalf("未恢复 docstring 实例的根 4: %s", out)
	}
}

// B. 前提不满足走结构化 not_applicable（不是崩、不是假 solved）：t4 对偶数 n 必须拒绝。
func TestRunSkillRichNotApplicableIsStructured(t *testing.T) {
	r := newRichTestRunner(t)
	ch := &ctfplatform.Challenge{Title: "e2e", Category: "crypto"}
	out, ok := r.RunSkillRich(context.Background(), "ctf_sage_t4_boneh_durfee", ch, map[string]any{
		"n": 100, // 偶数 → not_applicable
		"e": 65537,
	})
	if !ok {
		t.Fatalf("结构化拒绝不应让子进程失败: %s", out)
	}
	if !strings.Contains(out, "not_applicable") {
		t.Fatalf("未按契约返回 not_applicable: %s", out)
	}
}

// C. 参数错误也是结构化 note（不崩）。
// 注意：共用子进程契约用 json.dumps 默认 ensure_ascii=True（ASCII 安全，避开
// Windows GBK 控制台坑），中文 note 以 \uXXXX 转义形态出现——判据用 "ok": false
// 与出错参数原值回显，不依赖解码形态。
func TestRunSkillRichBadParamsStructured(t *testing.T) {
	r := newRichTestRunner(t)
	ch := &ctfplatform.Challenge{Title: "e2e", Category: "crypto"}
	out, _ := r.RunSkillRich(context.Background(), "ctf_sage_t5_dlp_bsgs_ph", ch, map[string]any{
		"g": "not-an-int",
	})
	if !strings.Contains(out, `"ok": false`) && !strings.Contains(out, `"ok":false`) {
		t.Fatalf("参数错误未结构化: %s", out)
	}
	if !strings.Contains(out, "not-an-int") {
		t.Fatalf("错误 note 未回显出错参数: %s", out)
	}
}

// D. extra 覆盖 description 正则提取值（数学参数优先，不许被猜的 key/text 覆盖）。
func TestRunSkillRichExtraOverridesExtracted(t *testing.T) {
	r := newRichTestRunner(t)
	// description 里埋 "密文: 999" 诱导提取；extra 的 modulus/poly 必须赢。
	ch := &ctfplatform.Challenge{
		Title: "e2e", Category: "crypto",
		Description: "密文: 999",
	}
	out, ok := r.RunSkillRich(context.Background(), "ctf_sage_t1_coppersmith", ch, map[string]any{
		"modulus": 10001,
		"poly":    []any{9779, 5000, 10, 1},
	})
	if !ok {
		t.Fatalf("RunSkillRich 失败: %s", out)
	}
	if !strings.Contains(out, "4") {
		t.Fatalf("extra 参数未生效（被提取值覆盖？）: %s", out)
	}
}
