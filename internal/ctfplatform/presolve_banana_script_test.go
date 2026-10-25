package ctfplatform

// presolve_banana_script_test.go —— bananascript 链 Go 化回归（真实端到端）。
//
// 载荷 = CSAW-Quals 2017 rev/bananaScript（banana.script，NYU CTF Bench 随迁件）；
// 官方锚 = flag_sha256 2819d24b…（题库 JSON 单一真值源）。python 侧
// test_banana_script 已 PASS，本测试钉住 Go 侧同链等价。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const bsBananaRel = "2017q-rev-bananascript/banana.script"
const bsBananaQID = "ext_nyu_ctf_bench_2017q_rev_bananascript"

func bsBananaFixture(t *testing.T) (string, string) {
	t.Helper()
	jf := filepath.Join(ccPoolDir, "rev", bsBananaQID+".json")
	raw, err := os.ReadFile(jf)
	if err != nil {
		t.Skipf("题库 JSON 缺失: %v", err)
	}
	var d struct {
		FlagSHA256 string `json:"flag_sha256"`
	}
	if err := json.Unmarshal(raw, &d); err != nil || d.FlagSHA256 == "" {
		t.Skipf("题库 JSON 无 flag_sha256: %s", jf)
	}
	data, err := os.ReadFile(ccAttachPath(bsBananaRel))
	if err != nil {
		t.Skipf("真实载荷缺失: %v", err)
	}
	return string(data), d.FlagSHA256
}

func TestXHLJChain_BananaScriptReal(t *testing.T) {
	text, anchor := bsBananaFixture(t)
	if !bsIsBananaScript(text) {
		t.Fatalf("真实载荷未过触发门（token 规模/banana 词占比）")
	}
	flag := bsSolveText(text)
	if flag == "" {
		t.Fatalf("banana 解码链未命中（store 常量提取/crib/列约束任一环断）")
	}
	sum := sha256.Sum256([]byte(flag))
	if hex.EncodeToString(sum[:]) != anchor {
		t.Fatalf("解出 %q 未过官方锚", flag)
	}
}

func TestXHLJChain_BananaScriptRegistryPath(t *testing.T) {
	text, _ := bsBananaFixture(t)
	flags := tryBananaScript("", map[string]string{"banana.script": text})
	if len(flags) == 0 {
		t.Fatalf("注册表路径未命中")
	}
}

func TestXHLJChain_BananaScriptNegative(t *testing.T) {
	if bsIsBananaScript("plain text with many words but none of them bananas variants at all") {
		t.Fatalf("普通文本不应过触发门")
	}
	if flags := tryBananaScript("", map[string]string{"x": "hello world foo bar baz qux"}); flags != nil {
		t.Fatalf("普通文本不应命中: %v", flags)
	}
	if strings.Join([]string{}, "") != "" {
		t.Fatalf("unreachable")
	}
}
