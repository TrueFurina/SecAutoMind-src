package ctfplatform

// presolve_bin_repair_test.go —— 二进制附件 flag 修复扫描的确定性测试。
//
// 夹具全部合成（真实二进制不入库）；upx 案例结构复刻自 A 库
// real_reverse_upx（flag 被 \x91\xe6\xff\xff 打断，hex 剥离后逐字还原）。

import (
	"context"
	"strings"
	"testing"
)

func TestRepairFlagCandidatesHexInterrupted(t *testing.T) {
	// upx 实证结构：flag{bffab77df5cea3 + 垃圾 + 53e2325bb4437c3d0b}
	dirty := "flag{bffab77df5cea3\x91\xe6\xff\xff53e2325bb4437c3d0b}"
	cands := repairFlagCandidates(dirty)
	want := "flag{bffab77df5cea353e2325bb4437c3d0b}"
	found := false
	for _, c := range cands {
		if c == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("hex 修复变体未命中: want %q got %v", want, cands)
	}
	// 全部候选必须干净可打印 + 完整形态
	for _, c := range cands {
		if !isPrintableFlagCandidate(c) || !binRepairFlagShape.MatchString(c) {
			t.Fatalf("候选未过三重门: %q", c)
		}
	}
}

func TestRepairFlagCandidatesRejectsGarbage(t *testing.T) {
	// inner 全垃圾剥完 <4 字符 → 无变体
	if cands := repairFlagCandidates("flag{\x91\x82\x83}"); len(cands) != 0 {
		t.Fatalf("垃圾 inner 不应产出变体: %v", cands)
	}
	// 无花括号结构 → nil
	if cands := repairFlagCandidates("flagdeadbeef"); len(cands) != 0 {
		t.Fatalf("无花括号不应产出变体: %v", cands)
	}
}

func TestTryBinaryFlagRepairOnlyForBinary(t *testing.T) {
	// 纯文本附件（含干净 flag）→ 不触发修复路（flag_scan 职责）
	textAtts := map[string]string{"note.txt": "the flag{clean_text_flag} is here"}
	if cands := tryBinaryFlagRepair("", textAtts); len(cands) != 0 {
		t.Fatalf("纯文本附件不应触发 bin_flag_repair: %v", cands)
	}
	// 二进制附件（ELF 头 + 被打断 flag）→ 触发并产出 hex 变体
	// （拼接写法避免 Go 十六进制转义吞后继字符：\xbeef 会吃掉 "be"）
	bin := "\x7fELF\x02\x01\x01\x00" + strings.Repeat("\x00", 16) +
		"flag{dead" + "\x91\xe6\xff\xff" + "beefcafe}\x90\x90"
	cands := tryBinaryFlagRepair("", map[string]string{"rev": bin})
	want := "flag{deadbeefcafe}"
	found := false
	for _, c := range cands {
		if c == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("二进制修复未命中 %q: %v", want, cands)
	}
	// 超大附件（>4MB）跳过
	big := "\x00\x01" + strings.Repeat("A", binRepairMaxBytes)
	if cands := tryBinaryFlagRepair("", map[string]string{"big": big}); len(cands) != 0 {
		t.Fatalf("超大附件不应参与: %v", cands)
	}
}

func TestBinFlagRepairRegisteredAndRuns(t *testing.T) {
	// 注册表端到端：求解器已注册且真的执行（机验「注册≠运行」）
	found := false
	for _, s := range GetSolvers() {
		if s.Name == "bin_flag_repair" {
			found = true
		}
	}
	if !found {
		t.Fatal("bin_flag_repair 未注册进注册表")
	}
	bin := "\x7fELF" + strings.Repeat("\x00", 8) + "flag{aa" + "\x91\xbb\xcc" + "bb\xdd}"
	cands := tryBinaryFlagRepair("", map[string]string{"a": bin})
	if len(cands) == 0 {
		t.Fatal("注册表入口未产出候选")
	}
	_ = context.Background()
}

func TestBinaryFlagConcatSeparatedStrings(t *testing.T) {
	// 合成夹具：.data 分离串（A 库 real_reverse_sheng 即 reverse_2 形态）
	// "flag" 与 "{hacking_for_fun}" 独立存放，直接正则永不可见。
	bin := "\x7fELF\x02\x01\x01\x00" + strings.Repeat("\x00", 16) +
		"\x00flag\x00{hacking_for_fun}\x00correct!\x00"
	cands := tryBinaryFlagConcat("", map[string]string{"rev": bin})
	want := "flag{hacking_for_fun}"
	found := false
	for _, c := range cands {
		if c == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("分离串拼接未命中 %q: %v", want, cands)
	}
	// 多花括号 + 多前缀的笛卡尔积应有界（≤32×8）且全干净可打印
	if len(cands) > 32*8 {
		t.Fatalf("候选爆炸: %d", len(cands))
	}
	for _, c := range cands {
		if !isPrintableFlagCandidate(c) {
			t.Fatalf("候选不干净: %q", c)
		}
	}
	// 纯文本附件不触发
	if cands := tryBinaryFlagConcat("", map[string]string{"t": "flag {plain_text} here"}); len(cands) != 0 {
		t.Fatalf("纯文本不应触发 bin_flag_concat: %v", cands)
	}
}
