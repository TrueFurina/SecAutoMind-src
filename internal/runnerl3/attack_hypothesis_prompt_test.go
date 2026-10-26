package runnerl3

import (
	"strings"
	"testing"

	"secautomind-ai/internal/ctfplatform"
)

// P1-1 的**接线**验证：假设必须真的进到给模型的用户提示里。
// 只测 BuildAttackHypotheses/RenderAttackHypotheses 不够——第八条纪律：
// 「定义齐全 ≠ 接线」，函数存在但没人调用是最常见的假交付。

func TestUserPromptInjectsAttackHypotheses(t *testing.T) {
	ch := &ctfplatform.Challenge{
		Title:       "登录绕过",
		Category:    "web",
		Description: "登录接口 POST /login.php 存在 SQL 注入，参数 user 与 pass 直接拼进 SQL。",
	}
	ff := newTestFallback(&fakeModel{}, 2, 2)
	prompt := ff.buildUserPrompt(ch)

	if !strings.Contains(prompt, "攻击假设") {
		t.Fatalf("题面含明确 SQLi 线索，用户提示却没有注入攻击假设：\n%s", prompt)
	}
	if !strings.Contains(prompt, "sqli") {
		t.Fatalf("假设应含 sqli 类型：\n%s", prompt)
	}
	if !strings.Contains(prompt, "/login.php") {
		t.Fatalf("假设应带题面端点：\n%s", prompt)
	}
	if !strings.Contains(prompt, "线索") {
		t.Fatalf("假设应标注线索条数（让模型知道证据强度）：\n%s", prompt)
	}
}

// 无线索的题不得注入假设块（宁缺勿猜，否则等于把模型导向盲扫）。
func TestUserPromptOmitsHypothesesWhenNoClue(t *testing.T) {
	ch := &ctfplatform.Challenge{
		Title:       "普通杂项",
		Category:    "misc",
		Description: "这是一道普通的杂项题目。",
	}
	ff := newTestFallback(&fakeModel{}, 2, 2)
	prompt := ff.buildUserPrompt(ch)
	if strings.Contains(prompt, "攻击假设") {
		t.Fatalf("无线索时不得注入假设块：\n%s", prompt)
	}
}
