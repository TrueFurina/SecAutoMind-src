package ctfplatform

// presolve_trithemius_test.go —— Trithemius 位置移位求解器测试（2026-10-26）。
// 锚：HTB dynastic（sha256 7f88cb699084b607…，真密文做夹具——密文本身非答案）。

import "testing"

func TestTryTrithemiusDynasticShape(t *testing.T) {
	// HTB dynastic 真实密文（公开采源附件 output.txt 第二行，密文不是答案）
	ct := "DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL"
	flags := tryTrithemius(ct)
	if len(flags) == 0 {
		t.Fatal("位置移位正向未命中")
	}
	want := "DID_YOU_KNOW_ABOUT_THE_TRITHEMIUS_CIPHER"
	if !containsStr(flags[0], want) {
		t.Fatalf("解码内容不含预期明文片段: %v", flags[0])
	}
}

func TestTryTrithemiusNegativeDirection(t *testing.T) {
	// 负向加密的合成样例：明文自带 brand 前缀（FlagExam{...}）→ 反向枚举直接命中
	plain := "FlagExam{THE_QUICK_BROWN_FOX}"
	ct := trithemiusShift(plain, +1) // 加密用 +i
	flags := tryTrithemius(ct)
	if len(flags) == 0 || !containsStr(flags[0], "THE_QUICK") {
		t.Fatalf("负向枚举失败: %v", flags)
	}
}

func TestTryTrithemiusNonAlphaPreserved(t *testing.T) {
	// 非字母原样保留但**占位**（dynastic 题源 for i in range(len(m)) 语义：
	// 位置=全串索引，!/? 也推进）——"A!B?C" 正向 = A!D?G
	got := trithemiusShift("A!B?C", +1)
	if got != "A!D?G" {
		t.Fatalf("全索引语义错误: %q != %q", got, "A!D?G")
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
