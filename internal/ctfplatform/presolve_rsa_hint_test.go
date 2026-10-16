// presolve_rsa_hint_test.go —— rsa_hint_high_exp 求解器回归测试
// （hint=pow(e·p+e², q, n) 泄露 + 高偶指数 e=2^k，DASCTF/西湖论剑 10733 型）。
//
// 纪律（与本仓门禁约定一致）：①合成 fixture 正向回归（**不写真题参数进 PUBLIC 仓**）；
// ②变异用例（输入损坏/不适用必须 fail-closed 返回 nil，不许为转绿放松判据）。
// 固定素数（seed 10733）离线生成后作为常量固化，实例在测试内程序化构建，跨平台确定。
//
// 真题 10733 的真实还原由 cross-bench 子集测试（TestCrossBench_AttachmentSubset）
// 在本地（附件在库）用 sha256 机验；此处只用合成实例证明算法本体正确。

package ctfplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 160-bit 定素数（均 ≡3 mod 4），n=p·q≈319-bit；seed=10733 可复现。
const (
	hintHighExpP = "988279365242112920136192989766198431043316359871"
	hintHighExpQ = "756684643061238248718420871377157345079583862139"
)

// buildHintHighExpText 按真题输出形态构建题面：hint/c/n 各占一行，e 单独一行。
// plaintext 为实际消息明文（未做 rot）；eVal 为公钥指数。
func buildHintHighExpText(t *testing.T, plaintext string, eVal int64) string {
	t.Helper()
	p, ok1 := new(big.Int).SetString(hintHighExpP, 10)
	q, ok2 := new(big.Int).SetString(hintHighExpQ, 10)
	if !ok1 || !ok2 {
		t.Fatalf("固定素数解析失败")
	}
	n := new(big.Int).Mul(p, q)
	e := big.NewInt(eVal)
	m := new(big.Int).SetBytes([]byte(plaintext))
	if m.Cmp(n) >= 0 {
		t.Fatalf("明文不小于 n，fixture 无效")
	}
	c := new(big.Int).Exp(m, e, n)
	// hint = (e·p + e²)^q mod n
	base := new(big.Int).Add(new(big.Int).Mul(e, p), new(big.Int).Mul(e, e))
	hint := new(big.Int).Exp(base, q, n)
	return fmt.Sprintf("hint= %s\nc= %s\nn= %s\ne = %d\n", hint, c, n, eVal)
}

func TestRSAHighExpHint_PlainFlag(t *testing.T) {
	const flag = "flag{synthetic_hint_high_exp}"
	text := buildHintHighExpText(t, flag, 65536)
	got := tryRSAHighExpHint(text, nil)
	if len(got) == 0 {
		t.Fatalf("应解出 flag，实际返回空")
	}
	if got[0] != flag {
		t.Fatalf("flag 不符：got=%q want=%q", got[0], flag)
	}
}

// TestRSAHighExpHint_RotEncodedFlag 覆盖「明文是 rot13 编码 flag」的真题坑点：
// 明文 QNFPGS{…}=rot13(DASCTF{…})，求解器须返回**规范 flag**（rot 解码后）。
func TestRSAHighExpHint_RotEncodedFlag(t *testing.T) {
	const canonical = "DASCTF{synthetic_rot_check}"
	plain := rotLatin(canonical, 13, false)
	if !strings.HasPrefix(plain, "QNFPGS{") {
		t.Fatalf("fixture 前提不成立：rot13 后应得 QNFPGS{ 开头，实际 %q", plain)
	}
	text := buildHintHighExpText(t, plain, 65536)
	got := tryRSAHighExpHint(text, nil)
	if len(got) == 0 {
		t.Fatalf("rot 编码题应解出规范 flag，实际返回空")
	}
	if got[0] != canonical {
		t.Fatalf("应返回 rot 解码后的规范 flag：got=%q want=%q", got[0], canonical)
	}
}

// TestRSAHighExpHint_Real10733Hash 用本地真题附件做端到端 sha256 机验。
// 附件 task.py 被 git 排除（含实例数据，PUBLIC 仓禁入库）→ CI 检出差不到，
// 走 t.Skip（预期行为，非故障）；开发机在库时做真值机验。
func TestRSAHighExpHint_Real10733Hash(t *testing.T) {
	const want = "ac232bd941738e22cfcdd6585ae478c19cffbea15d713c00a70ac157485ca6a4" // cross_bench.json:10733
	path := filepath.Join("..", "..", "data", "questions_real_bench", "attachments", "10733", "task.py")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("本地无 10733 附件（git 排除，CI 属正常）：%v", err)
	}
	got := tryRSAHighExpHint(string(raw), nil)
	if len(got) == 0 {
		t.Fatalf("真题 10733 应解出，实际返回空")
	}
	sum := sha256.Sum256([]byte(got[0]))
	if hex.EncodeToString(sum[:]) != want {
		t.Fatalf("规范 flag sha256 不匹配：got=%s want=%s（flag=%q）",
			hex.EncodeToString(sum[:]), want, got[0])
	}
}

// TestRSAHighExpHint_FailClosed 变异用例：任一前提破坏都必须返回 nil（不许误报）。
func TestRSAHighExpHint_FailClosed(t *testing.T) {
	good := buildHintHighExpText(t, "flag{synthetic_hint_high_exp}", 65536)
	cases := []struct {
		name string
		text string
	}{
		{"hint 被篡改", strings.Replace(good, "hint= ", "hint= 9", 1)},
		{"缺少 n 行", stripLinePrefix(good, "n= ")},
		{"e 非 2 的幂", buildHintHighExpText(t, "flag{synthetic_hint_high_exp}", 65537)},
		{"完全无关文本", "这是一个与 RSA 无关的题目，没有 hint/c/n。"},
		{"空文本", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tryRSAHighExpHint(c.text, nil); len(got) != 0 {
				t.Fatalf("应 fail-closed 返回 nil，实际 %v", got)
			}
		})
	}
}

// stripLinePrefix 删除以 prefix 开头的那一行（用于构造「缺少某字段」的变异输入）。
func stripLinePrefix(text, prefix string) string {
	var out []string
	for _, ln := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), strings.TrimSpace(prefix)) {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

// 兜底：注册表求解器签名适配层不得与攻击实现脱节。
func TestRSAHintHighExp_RegisteredAdapter(t *testing.T) {
	text := buildHintHighExpText(t, "flag{synthetic_hint_high_exp}", 65536)
	if got := solveRSAHintHighExp(context.Background(), text, nil); len(got) == 0 {
		t.Fatalf("注册表适配层应返回同一结果")
	}
}
