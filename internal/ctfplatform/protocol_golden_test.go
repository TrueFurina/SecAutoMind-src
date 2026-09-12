package ctfplatform

// 双语言协议一致性机验（cross-language golden test）。
//
// 真值来源：西湖论剑真源 ctf_agent/ctfplatform/dasctf.py 的
// _parse_challenge / _strip_flag_wrapper —— 由 scripts/gen_protocol_golden.py
// 依据真源生成 testdata/protocol_golden.json（单一真值源，禁止手改）。
//
// 为什么需要它：本包对官方协议的解析（题面字段、flag 外壳剥离）是决赛提交链路的
// 地基，单靠人眼比对源码极易漏掉分支差异（例如标题兜底顺序、题型同义词、
// REAL-xx 附件名判型）。这里用同一组 fixture 让 Python 真源与 Go 实现同场竞技，
// 任何一侧行为漂移都会被逐字段点名。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type protocolFixture struct {
	Challenges []struct {
		Name string          `json:"name"`
		Item json.RawMessage `json:"item"`
	} `json:"challenges"`
	Flags []string `json:"flags"`
}

type protocolGolden struct {
	Challenges []struct {
		Name          string `json:"name"`
		ID            string `json:"id"`
		Title         string `json:"title"`
		Category      string `json:"category"`
		Description   string `json:"description"`
		FlagFormat    string `json:"flag_format"`
		Score         int    `json:"score"`
		HasInstance   bool   `json:"has_instance"`
		HasAttachment bool   `json:"has_attachment"`
	} `json:"challenges"`
	Flags []struct {
		Input    string `json:"input"`
		Expected string `json:"expected"`
	} `json:"flags"`
}

func loadProtocolPair(t *testing.T) (protocolFixture, protocolGolden) {
	t.Helper()
	dir := filepath.Join("testdata")
	fxRaw, err := os.ReadFile(filepath.Join(dir, "protocol_fixtures.json"))
	if err != nil {
		t.Fatalf("读取 fixture 失败: %v", err)
	}
	gdRaw, err := os.ReadFile(filepath.Join(dir, "protocol_golden.json"))
	if err != nil {
		t.Fatalf("读取 golden 失败（请先跑 scripts/gen_protocol_golden.py）: %v", err)
	}
	var fx protocolFixture
	if err := json.Unmarshal(fxRaw, &fx); err != nil {
		t.Fatalf("解析 fixture 失败: %v", err)
	}
	var gd protocolGolden
	if err := json.Unmarshal(gdRaw, &gd); err != nil {
		t.Fatalf("解析 golden 失败: %v", err)
	}
	if len(fx.Challenges) != len(gd.Challenges) {
		t.Fatalf("fixture 与 golden 题目数不一致（%d vs %d）——请重跑生成器",
			len(fx.Challenges), len(gd.Challenges))
	}
	return fx, gd
}

// TestProtocolGoldenChallengeParsing 逐字段比对题目解析结果。
// 一次跑完全部用例并汇总所有差异，避免"修一条报一条"的低效循环。
func TestProtocolGoldenChallengeParsing(t *testing.T) {
	fx, gd := loadProtocolPair(t)

	var diffCount int
	for i, want := range gd.Challenges {
		got := parseChallenge(fx.Challenges[i].Item)
		if got.ID != want.ID {
			t.Errorf("[%s] id: 真源=%q Go=%q", want.Name, want.ID, got.ID)
			diffCount++
		}
		if got.Title != want.Title {
			t.Errorf("[%s] title: 真源=%q Go=%q", want.Name, want.Title, got.Title)
			diffCount++
		}
		if got.Category != want.Category {
			t.Errorf("[%s] category: 真源=%q Go=%q", want.Name, want.Category, got.Category)
			diffCount++
		}
		if got.Description != want.Description {
			t.Errorf("[%s] description: 真源=%q Go=%q", want.Name, want.Description, got.Description)
			diffCount++
		}
		if got.FlagFormat != want.FlagFormat {
			t.Errorf("[%s] flag_format: 真源=%q Go=%q", want.Name, want.FlagFormat, got.FlagFormat)
			diffCount++
		}
		if got.Score != want.Score {
			t.Errorf("[%s] score: 真源=%d Go=%d", want.Name, want.Score, got.Score)
			diffCount++
		}
		if got.HasInstance != want.HasInstance {
			t.Errorf("[%s] has_instance: 真源=%v Go=%v", want.Name, want.HasInstance, got.HasInstance)
			diffCount++
		}
		if got.HasAttachment != want.HasAttachment {
			t.Errorf("[%s] has_attachment: 真源=%v Go=%v", want.Name, want.HasAttachment, got.HasAttachment)
			diffCount++
		}
	}
	if diffCount > 0 {
		t.Errorf("共 %d 处与 Python 真源不一致（真值是 Python 侧）", diffCount)
	}
}

// TestProtocolGoldenFlagStripping 比对 flag 外壳剥离（手册第 7 条：
// 提交时仅需提交 {} 内内容）。剥错 = 正确 flag 被判错，且每题机会有限。
func TestProtocolGoldenFlagStripping(t *testing.T) {
	_, gd := loadProtocolPair(t)

	var diffCount int
	for _, c := range gd.Flags {
		if got := StripFlagWrapper(c.Input); got != c.Expected {
			t.Errorf("StripFlagWrapper(%q): 真源=%q Go=%q", c.Input, c.Expected, got)
			diffCount++
		}
	}
	if diffCount > 0 {
		t.Errorf("共 %d 处剥离结果与 Python 真源不一致", diffCount)
	}
}
