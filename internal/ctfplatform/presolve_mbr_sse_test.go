package ctfplatform

// presolve_mbr_sse_test.go —— MBR SSE 校验链 Go 化回归（真实端到端 + 仿真自检）。
//
// 载荷 = CSAW-Quals 2017 rev realism（main.bin，512B MBR，NYU CTF Bench 随迁件）；
// 官方锚 = flag_sha256（题库 JSON 单一真值源：bb6da24e…）。python 侧
// test_mbr_sse_verify 已 PASS，本测试钉住 Go 侧同链等价 + 仿真自检双保险。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const mbrRealismRel = "2017q-rev-realism/main.bin"
const mbrRealismQID = "ext_nyu_ctf_bench_2017q_rev_realism"

func mbrRealismFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	jf := filepath.Join(ccPoolDir, "rev", mbrRealismQID+".json")
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
	data, err := os.ReadFile(filepath.Join(ccAttachDir, mbrRealismRel))
	if err != nil {
		t.Skipf("真实载荷缺失: %v", err)
	}
	return data, d.FlagSHA256
}

func TestXHLJChain_MbrSseReal(t *testing.T) {
	data, anchor := mbrRealismFixture(t)
	if !isMbrSseVerify(data) {
		t.Fatalf("真实载荷未过触发门（512B/55AA/三件套）")
	}
	flag := solveMbrSse(data)
	if flag == nil {
		t.Fatalf("MBR SSE 链未命中（提取/掩码校验/递推/消歧任一环断）")
	}
	sum := sha256.Sum256(flag)
	if hex.EncodeToString(sum[:]) != anchor {
		t.Fatalf("解出 %q 未过官方锚", flag)
	}
	// 仿真自检：完整 psadbw 链复核（solve 内未用的独立验证路径）
	if !simulateMbrSse(data, flag) {
		t.Fatalf("仿真复核失败——解与期望表不自洽")
	}
}

func TestXHLJChain_MbrSseRegistryPath(t *testing.T) {
	data, _ := mbrRealismFixture(t)
	flags := tryMbrSse("", map[string]string{"main.bin": string(data)})
	if len(flags) == 0 {
		t.Fatalf("注册表路径未命中")
	}
}

func TestXHLJChain_MbrSseNegative(t *testing.T) {
	if isMbrSseVerify([]byte(make([]byte, 512))) {
		t.Fatalf("全零 512B 不应过触发门")
	}
	if flags := tryMbrSse("", map[string]string{"x": string(make([]byte, 512))}); flags != nil {
		t.Fatalf("全零 512B 不应命中: %v", flags)
	}
}
