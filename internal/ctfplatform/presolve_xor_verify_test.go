package ctfplatform

// presolve_xor_verify_test.go —— XOR+查表 反推链 Go 化回归（真实端到端）。
//
// 载荷 = CSAW 2023 quals rev/rox（food，59KB ELF，NYU CTF Bench 随迁件，盘上实测
// 在位）；官方锚 = flag_sha256（题库 JSON 单一真值源）。python 侧
// test_rev_xor_verify 已 PASS，本测试钉住 Go 侧同链等价。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const xvRoxRel = "2023q-rev-rox/food"
const xvRoxQID = "ext_nyu_ctf_bench_2023q_rev_rox"

func xvRoxFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	if _, err := os.Stat(ccAttachPath(xvRoxRel)); err != nil {
		t.Skipf("真实载荷缺失: %v", err)
	}
	jf := filepath.Join(ccPoolDir, "rev", xvRoxQID+".json")
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
	data, err := os.ReadFile(ccAttachPath(xvRoxRel))
	if err != nil {
		t.Skipf("载荷读取失败: %v", err)
	}
	return data, d.FlagSHA256
}

func TestXHLJChain_XorVerifyReal(t *testing.T) {
	blob, anchor := xvRoxFixture(t)
	flags := solveXorVerify(blob, anchor)
	if len(flags) == 0 {
		t.Fatalf("XOR+查表 反推链未命中（key/表/常量串提取或约束求解任一环断）")
	}
	sum := sha256.Sum256([]byte(flags[0]))
	if hex.EncodeToString(sum[:]) != anchor {
		t.Fatalf("解出 %q 未过官方锚", flags[0])
	}
}

func TestXHLJChain_XorVerifyNegative(t *testing.T) {
	if flags := solveXorVerify([]byte("plain text, not an ELF"), ""); flags != nil {
		t.Fatalf("非 ELF 输入不应命中: %v", flags)
	}
	if flags := solveXorVerify([]byte("\x7fELF without verify symbol \x02\x01\x01"), ""); flags != nil {
		t.Fatalf("无 _Z6verify 触发门不应进入: %v", flags)
	}
}
