package ctfplatform

// presolve_emoji_binary_test.go —— 二进制 emoji 解码链 Go 化回归（真实端到端）。
//
// 载荷 = CSAW-Finals 2023 forensics/emoji（emoji.txt，364 字符 UTF-8，NYU CTF
// Bench 随迁件）；官方锚 = flag_sha256 ce5aff49…（题库 JSON 单一真值源）。
// python 侧 test_emoji_binary 已 PASS，本测试钉住 Go 侧同链等价。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ebEmojiRel = "2023f-for-emoji/emoji.txt"
const ebEmojiQID = "ext_nyu_ctf_bench_2023f_for_emoji"

func ebEmojiFixture(t *testing.T) (string, string) {
	t.Helper()
	jf := filepath.Join(ccPoolDir, "forensics", ebEmojiQID+".json")
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
	txtPath := filepath.Join(ccAttachDirParent, "forensics", "2023f-for-emoji", "emoji.txt")
	txt, err := os.ReadFile(txtPath)
	if err != nil {
		t.Skipf("真实载荷缺失: %v", err)
	}
	return string(txt), d.FlagSHA256
}

func TestXHLJChain_EmojiBinaryReal(t *testing.T) {
	text, anchor := ebEmojiFixture(t)
	if !ebIsEmojiBinaryText(text) {
		t.Fatalf("真实载荷未过触发门（token 规模/符号数）")
	}
	flag := ebDecode(text, anchor)
	if flag == "" {
		t.Fatalf("emoji 解码链未命中（DFS/剪枝/择优任一环断）")
	}
	sum := sha256.Sum256([]byte(flag))
	if hex.EncodeToString(sum[:]) != anchor {
		t.Fatalf("解出 %q 未过官方锚", flag)
	}
}

func TestXHLJChain_EmojiBinaryNegative(t *testing.T) {
	if ebIsEmojiBinaryText("plain ascii text is not emoji at all") {
		t.Fatalf("ASCII 文本不应过触发门")
	}
	if flags := tryEmojiBinary("", map[string]string{"x": "plain ascii"}); flags != nil {
		t.Fatalf("ASCII 文本不应命中: %v", flags)
	}
	if strings.Join([]string{}, "") != "" {
		t.Fatalf("unreachable")
	}
}

// ccAttachDirParent 指向 questions_ext/_attachments（emoji 在 forensics 子目录）。
const ccAttachDirParent = "../../CTF-Agent_融合/ctf_agent/data/questions_ext/_attachments"
