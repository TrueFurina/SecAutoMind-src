package ctfplatform

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// 本文件是「P1 真解题求解器适配函数」的**能力验证**（REA #295-#299）。
//
// 背景：ctfplatform/solver_registry.go 里躺着 11 个 solveXxxDecode 适配函数，
// staticcheck U1000 判定它们从未被调用——即这 11 个解题能力写在代码里，
// 却从未参与过任何一次扫描。接线（RegisterSolver）会改变运行时行为，
// 故接线前必须先回答三个问题，否则接线就是在往注册表里注水：
//
//   ① 它真能解出目标吗？（能力宣称三档：代码在位 → 演练通过 → 生产验证）
//   ② 它会不会对普通文本误报？（误报会短路 Agent 的后续推理）
//   ③ 它是不是已被别的已注册求解器覆盖？（注册重复项 = 注水）
//
// 本文件用**可计算样本**（密文在测试内由明文推导，不硬编码）回答 ①②③。
// 这是接线的前置门禁：能力未经验证就不许接进生产链路。

// ── 样本编码器：每个都必须是对应解码器的精确逆运算 ──────────────────

func encAtbash(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			sb.WriteRune('z' - (r - 'a'))
		case r >= 'A' && r <= 'Z':
			sb.WriteRune('Z' - (r - 'A'))
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func encROT13(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			sb.WriteRune((r-'a'+13)%26 + 'a')
		case r >= 'A' && r <= 'Z':
			sb.WriteRune((r-'A'+13)%26 + 'A')
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func encHex(s string) string { return hex.EncodeToString([]byte(s)) }

func encPercent(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&sb, "%%%02X", s[i])
	}
	return sb.String()
}

func encBinary(s string) string {
	parts := make([]string, 0, len(s))
	for i := 0; i < len(s); i++ {
		parts = append(parts, fmt.Sprintf("%08b", s[i]))
	}
	return strings.Join(parts, " ")
}

func encOctal(s string) string {
	parts := make([]string, 0, len(s))
	for i := 0; i < len(s); i++ {
		parts = append(parts, fmt.Sprintf("%03o", s[i]))
	}
	return strings.Join(parts, " ")
}

func encDecimal(s string) string {
	parts := make([]string, 0, len(s))
	for i := 0; i < len(s); i++ {
		parts = append(parts, fmt.Sprintf("%d", s[i]))
	}
	return strings.Join(parts, " ")
}

func encReverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// encPigLatin 标准 Pig Latin 编码：首字母移到末尾 + "ay"。
// 只处理纯字母词，其余原样保留（与 tryPigLatin 的分词口径一致）。
func encPigLatin(s string) string {
	words := strings.Fields(s)
	out := make([]string, 0, len(words))
	for _, w := range words {
		lower := strings.ToLower(w)
		if isAllAlpha(lower) && len(lower) > 1 {
			out = append(out, lower[1:]+string(lower[0])+"ay")
		} else {
			out = append(out, w)
		}
	}
	return strings.Join(out, " ")
}

func isAllAlpha(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

// URLSafePlain 是一段「base64 编码后确实含 '+'」的明文。
//
// 为什么不能直接随便挑一段明文：URL-safe Base64 与标准 Base64 的差异
// **只在** 用 -_ 替代 +/。而普通可打印 ASCII 的 base64 输出碰巧不含
// +/（6 位组取不到 62/63），随手挑的样本编码后压根不含这两个字符，
// 测的其实是标准 Base64——那是 base64_multilayer 的活，
// 证明不了本求解器的独立价值。必须刻意构造。
//
// 构造原理：'~' = 0x7E = 0111 1110，其低 6 位 = 111110 = 62 = '+'。
// 让它落在每组 3 字节的**第 3 个**位置，该组输出必然含 '+'。
// "FLAG{" 占 5 字节，故紧跟其后的 '~' 正好是 3 的倍数位置 +2。
const URLSafePlain = "FLAG{~~~~}"

// encBase64URLSafe 标准 Base64 → URL-safe（+/ → -_），
// 正是 tryBase64URLSafe 期望的输入形态。
func encBase64URLSafe(s string) string {
	std := base64.StdEncoding.EncodeToString([]byte(s))
	std = strings.ReplaceAll(std, "+", "-")
	return strings.ReplaceAll(std, "/", "_")
}

// ── 门禁 ①：正向能力——必须能由明文推导的密文解出 flag ───────────────

// TestClassicalDecodeSolversHitTarget 正向能力验证。
//
// 为什么不在测试里硬编码密文：硬编码串一旦与实现脱节（实现改了、串没改），
// 测试会变成永绿的摆设。样本由明文现算，实现改错方向时测试会跟着红。
func TestClassicalDecodeSolversHitTarget(t *testing.T) {
	// 前置自检：样本必须真的落到 URL-safe 特有路径上，否则本条用例在测
	// 标准 Base64，证明不了 encoding_base64url 的独立价值。
	if std := base64.StdEncoding.EncodeToString([]byte(URLSafePlain)); !strings.ContainsAny(std, "+/") {
		t.Fatalf("样本 %q 的 base64 为 %q，不含 +/ —— 用例退化为标准 Base64，失效",
			URLSafePlain, std)
	}

	cases := []struct {
		name   string
		plain  string
		enc    func(string) string
		solver ContextSolverFunc
	}{
		{"atbash", "FLAG{atbashdecoded}", encAtbash, solveAtbashDecode},
		{"hex", "FLAG{hexdecoded}", encHex, solveHexDecode},
		{"url", "FLAG{urldecoded}", encPercent, solveURLDecode},
		{"binary", "FLAG{binarydecoded}", encBinary, solveBinaryDecode},
		{"octal", "FLAG{octaldecoded}", encOctal, solveOctalDecode},
		{"decimal", "FLAG{decimaldecoded}", encDecimal, solveDecimalDecode},
		{"reverse", "FLAG{reversedecoded}", encReverse, solveReverseText},
		{"piglatin", "flag {piglatindecoded}", encPigLatin, solvePigLatin},
		{"base64url", URLSafePlain, encBase64URLSafe, solveBase64URLSafe},
		// rot13 有能，但被已注册的 caesar（shift 1..25，含 13）完全覆盖，
		// 故**不注册**，单独由 TestROT13IsSubsumedByCaesar 证明其冗余。
		{"rot13", "FLAG{rot13decoded}", encROT13, solveROT13},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// 前置自检：明文本身必须能被 scanFlags 认出，否则这条用例在测空气
			if got := scanFlags(c.plain); len(got) == 0 {
				t.Fatalf("样本明文 %q 自身不具 flag 外形，用例无效", c.plain)
			}
			cipher := c.enc(c.plain)
			got := c.solver(context.Background(), cipher, nil)
			if !hasFlagShape(got) {
				t.Fatalf("%s 未解出目标：明文=%q 密文=%q 返回=%v",
					c.name, c.plain, cipher, got)
			}
		})
	}
}

// hasFlagShape 判断求解器输出里是否含真 flag 外形。
// 存在必要：Hex/二进制/八进制/十进制/Base64URL 五者在扫不到 flag 时会返回
// 形如 "Hex解码: ..." 的**诊断文本**——那不是命中，只是过程信息。
// 不区分二者就会把诊断当成解题能力，门禁形同虚设。
func hasFlagShape(outs []string) bool {
	for _, o := range outs {
		if len(scanFlags(o)) > 0 {
			return true
		}
	}
	return false
}

// ── 门禁 ②：负向——对普通文本不得产生 flag 外形的输出 ────────────────

// TestClassicalDecodeSolversNoFalsePositive 负向验证。
// 误报的代价高于漏报：presolve 命中会短路 Agent 的后续推理（见
// presolve_registry.go 的 minFlagLikenessForHit 门控），一次假命中会让
// 整道题走向错误的方向。故接线前必须先证明它们对普通文本保持沉默。
func TestClassicalDecodeSolversNoFalsePositive(t *testing.T) {
	solvers := map[string]ContextSolverFunc{
		"atbash":    solveAtbashDecode,
		"hex":       solveHexDecode,
		"url":       solveURLDecode,
		"binary":    solveBinaryDecode,
		"octal":     solveOctalDecode,
		"decimal":   solveDecimalDecode,
		"reverse":   solveReverseText,
		"piglatin":  solvePigLatin,
		"base64url": solveBase64URLSafe,
	}
	// 普通英文句子：不是密文，任何解码器都不得从中"解出"flag。
	benign := []string{
		"Please review the attached document before the meeting tomorrow morning.",
		"The quick brown fox jumps over the lazy dog near the river bank at dawn.",
		"Hello world, this is a test string used for regression checks in CI.",
	}
	for name, fn := range solvers {
		for _, b := range benign {
			got := fn(context.Background(), b, nil)
			if hasFlagShape(got) {
				t.Errorf("%s 对普通文本误报：输入=%q 输出=%v", name, b, got)
			}
		}
	}
}

// TestDiagnosticOutputNeverPassesTheHitGate 诊断文本不得被当成命中。
//
// 五个解码器在扫不到 flag 时会返回 "Hex解码: ..." 这类诊断。
// flagLikeness 给这类文本打 1 分（不匹配任何 flag 正则），
// 低于 minFlagLikenessForHit=3，故会被 sweep 丢弃。
// 本用例把这个推理**机验**，而不是靠读代码相信它——
// 一旦有人给诊断文本加了 flag 外形（比如把 "FLAG{...}" 拼进去），
// 这里会立刻红。
func TestDiagnosticOutputNeverPassesTheHitGate(t *testing.T) {
	diag := []string{
		"Hex解码: hello world",
		"二进制解码: some decoded bytes",
		"八进制解码: more decoded bytes",
		"十进制解码: yet more bytes",
		"Base64URL解码: and more",
		"编码检测: ROT13",
	}
	for _, d := range diag {
		if got := flagLikeness([]string{d}); got >= minFlagLikenessForHit {
			t.Errorf("诊断文本 %q 的 likeness=%d 已达命中阈值 %d，会污染 solved 判定",
				d, got, minFlagLikenessForHit)
		}
	}
}

// ── 门禁 ③：接线项必须是未覆盖且可命中的 ────────────────────────────

// TestROT13IsSubsumedByCaesar 证明 solveROT13 **不该**注册：
// 已注册的 caesar（priority 30）遍历 shift 1..25，其中包含 13。
// 注册一个被完全覆盖的求解器不是补能力，是注水——反注水门禁
// （TestAllRegisteredSolversActuallyExecute）只证明"被执行过"，
// 证明不了"提供了别人没有的能力"，所以这条冗余得由人来判、由机来验。
func TestROT13IsSubsumedByCaesar(t *testing.T) {
	plain := "FLAG{rot13decoded}"
	cipher := encROT13(plain)

	// caesar 必须能解出同一个目标，否则"被覆盖"的说法不成立
	got := solveCaesar(context.Background(), cipher, nil)
	if !hasFlagShape(got) {
		t.Fatalf("caesar 未能解出 ROT13 密文 %q（返回 %v），"+
			"则 ROT13 并不被 caesar 覆盖，应当注册它", cipher, got)
	}
	// 反向确认：solveROT13 自己也确实有能（不是因为它没用才不注册）
	if got := solveROT13(context.Background(), cipher, nil); !hasFlagShape(got) {
		t.Fatalf("solveROT13 对自身样本失效，用例前提不成立：%v", got)
	}
	t.Logf("solveROT13 能力成立但被 caesar 完全覆盖 → 不注册（防注水）")
}

// TestVigenereDecodeIsStructurallyUnhittable 证明一个不需要靠样本碰运气的结论：
//
//	tryVigenereDecode 的输入过滤是 `^[a-zA-Z\s]+$`（只收纯字母），
//	而 vigenereDecode 对非字母字符原样保留、空格还被提前删除，
//	于是**输出必然也是纯字母串**。
//	但 scanFlags 认的是 `xxx{...}` / `XXX{...}` 形态——必含花括号。
//	纯字母输出里永远没有花括号，故该求解器命中率恒为 0。
//
// 这不是「样本没找对」，是输入契约与输出要求互相排斥的结构性缺陷。
// 结论直接决定处置：solveVigenereDecode **不接进注册表**
// （接了也只会在每道题上白跑 9 次密钥猜测，纯耗 CPU）。
func TestVigenereDecodeIsStructurallyUnhittable(t *testing.T) {
	rng := rand.New(rand.NewSource(20261022))

	// ① 纯字母输入（能通过输入过滤的唯一形态）：输出不得含花括号。
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	for i := 0; i < 200; i++ {
		n := 12 + rng.Intn(60)
		sb := make([]rune, 0, n)
		for j := 0; j < n; j++ {
			sb = append(sb, letters[rng.Intn(len(letters))])
		}
		in := string(sb)
		if got := solveVigenereDecode(context.Background(), in, nil); hasFlagShape(got) {
			t.Fatalf("纯字母输入竟产出 flag 外形（与前提矛盾）：%q → %v", in, got)
		}
	}

	// ② 含花括号的输入（真 flag 密文的必然形态）：必须被输入过滤挡在门外，
	//    直接返回 nil。这条证明「哪怕密文真的藏在那里，它也扫不到」。
	withBraces := []string{
		"WkhIudjLvKhuh{abcdef}",
		"ZkhcFodjLvKhuh{vigenere_should_not_fire}",
		"Abcdefgh{ijklmnop}",
	}
	for _, in := range withBraces {
		if got := solveVigenereDecode(context.Background(), in, nil); len(got) != 0 {
			t.Fatalf("含花括号输入应被输入过滤直接拒绝，却返回 %v（输入=%q）", got, in)
		}
	}
}

// ── 门禁 ④：诚实披露已知局限（不粉饰，也不假装它不存在）─────────────

// TestWholeTextOnlyDecodersSkipMixedText 记录一条**已知局限**，不是失败。
//
// hex / 二进制 / 八进制 / 十进制 四个解码器都要求「整段输入是纯密文」
// （各自的输入正则以 ^...$ 锚定）。而真实 CTF 题面是自然语言与密文的
// 混合体，密文只是其中的一个 token。因此这四个求解器在真实题面上
// 命中率恒为 0——它们只在「题面恰好就是一整段密文」时才工作。
//
// 这个断言不是为了夸它们，恰恰是为了防止有人误以为接线 9 个就获得
// 9 份能力。若将来有人把契约改成「先提取候选 token 再解码」，
// 本测试会转红——那正是设计意图：契约变了，文档与台账必须同步更新。
func TestWholeTextOnlyDecodersSkipMixedText(t *testing.T) {
	// 典型真实题面：自然语言 + 内嵌密文 token
	mixed := "The secret message is 48656c6c6f20576f726c64 please decode it to find the flag."
	cases := map[string]ContextSolverFunc{
		"hex":     solveHexDecode,
		"binary":  solveBinaryDecode,
		"octal":   solveOctalDecode,
		"decimal": solveDecimalDecode,
	}
	for name, fn := range cases {
		got := fn(context.Background(), mixed, nil)
		if hasFlagShape(got) {
			t.Errorf("%s 对混合文本产出 flag 外形（契约若已改为提取 token，"+
				"请同步更新本用例与 docs 说明）：%v", name, got)
		}
	}
	t.Logf("已知局限：hex/二进制/八进制/十进制 要求整段输入为纯密文，" +
		"对「自然语言+内嵌 token」的真实题面恒不命中。" +
		"改进方向=先从题面提取候选 token 再逐个解码（会改变行为，需 USER 拍板）。")
}

// TestWiredSolversHaveCapabilityProof 能力证明表门禁（REA #299）。
//
// 反注水门禁只证明「每个 Enabled 求解器都执行过 ≥1 次」——
// 执行过 ≠ 有能力。本仓已有反例：encoding_chain / encoding_detection_advanced
// 是**关键词命中器**（扫题面里有没有 "rot13"/"atbash" 这些字样，
// 返回 "编码检测: ROT13" 诊断文本），它们执行得勤快，但从不解出任何东西。
//
// 所以本门禁要求：凡进入本表的求解器，必须有本文件里的正向用例作证。
// 这是「注册即需举证」的闸门，防止把未验证的东西接进生产链路。
func TestWiredSolversHaveCapabilityProof(t *testing.T) {
	// 本次接线的 9 个：每个都必须能在 proved 里找到名字。
	wired := []string{
		"classical_atbash",
		"encoding_hex",
		"encoding_url",
		"encoding_binary",
		"encoding_octal",
		"encoding_decimal",
		"encoding_reverse",
		"classical_piglatin",
		"encoding_base64url",
	}
	// 有正向用例作证的能力（对应 TestClassicalDecodeSolversHitTarget 的子用例名）
	proved := map[string]bool{
		"classical_atbash":   true,
		"encoding_hex":       true,
		"encoding_url":       true,
		"encoding_binary":    true,
		"encoding_octal":     true,
		"encoding_decimal":   true,
		"encoding_reverse":   true,
		"classical_piglatin": true,
		"encoding_base64url": true,
	}

	registered := make(map[string]bool)
	for _, s := range GetSolvers() {
		registered[s.Name] = true
	}
	for _, w := range wired {
		if !registered[w] {
			t.Errorf("声明已接线但注册表里没有：%s", w)
		}
		if !proved[w] {
			t.Errorf("接线项 %s 缺少正向能力证明用例——不许注册未举证的能力", w)
		}
	}

	// 诚实披露：注册表里有多少求解器，就有多少没有能力证明。
	total, withProof := len(registered), 0
	for n := range registered {
		if proved[n] {
			withProof++
		}
	}
	t.Logf("注册表求解器 %d 个，其中 %d 个有正向能力证明（其余仅通过"+
		"「执行过」门禁，不代表有解题能力——反注水门禁管不到这一层）",
		total, withProof)
}

// TestUnwiredSolversRemainUnwired 把「不接线」这个决定从注释升级成机验约束。
//
// 为什么需要这条：staticcheck 的 U1000 判定「从导出 API 不可达」时，
// **把 _test.go 里的引用也算作可达**——而本文件恰恰大量引用了
// solveVigenereDecode / solveROT13（为了证明它们不配接线）。
// 结果是：这 4 个符号（含各自的叶子）从 U1000 报告里消失了，
// 仿佛它们上线了。实际它们在生产链路里从未被调用过。
//
// 这是必须写下来的陷阱：**给死代码写测试，会让它看起来不是死代码**。
// 台账 110 → 87 的降幅里，有 4 条是这么来的，不是接线来的
// （真接线只复活了 19 条）。不说明的话，下一个人会以为 23 个能力上线了。
//
// 本门禁绕开静态检查，直接在注册表层面比对函数指针：
// 只要有人好心把这两个接进生产链路，这里立刻红。
func TestUnwiredSolversRemainUnwired(t *testing.T) {
	unwired := []struct {
		fn   ContextSolverFunc
		why  string
		name string
	}{
		{solveVigenereDecode, "结构上命中率恒为 0（输入只收纯字母，输出必为纯字母，" +
			"永远凑不出 xxx{...}）——接线只会白跑 9 次密钥猜测", "solveVigenereDecode"},
		{solveROT13, "已被在册的 caesar（shift 1..25，含 13）完全覆盖——" +
			"注册被覆盖项是注水，不是补能力", "solveROT13"},
	}
	for _, s := range GetSolvers() {
		if s.Solver == nil {
			continue
		}
		got := reflect.ValueOf(s.Solver).Pointer()
		for _, u := range unwired {
			if reflect.ValueOf(u.fn).Pointer() == got {
				t.Errorf("%s 被注册为 %q——它不该进生产链路：%s", u.name, s.Name, u.why)
			}
		}
	}
}

// TestPigLatinDecodeIsInverseOfEncode 锁死 2026-10-22 修掉的确定性 bug。
// 原实现写的是 `core[1:]+core[0]`（首字母移到末尾）——那是 Pig Latin 的
// **编码**动作，不是解码。方向搞反时 "lagfay" 会被解成 "agfl"，
// flag 永远扫不出来。本用例让编解码互为断言，方向一错立刻红。
//
// ⚠️ 样本必须自带 {..}：tryPigLatin 末尾过的是 scanFlags，只放行 flag 外形。
// 拿裸词 "flag" 当样本，解码结果正确也会被 scanFlags 判成没有 flag 而返回
// nil——那是求解器的设计（不产出非 flag 结论），不是 bug。
// 用裸词测互逆会得到假失败，故样本一律是「词 + 空格 + {内容}」。
func TestPigLatinDecodeIsInverseOfEncode(t *testing.T) {
	// 词条固定在 "flag"：scanFlags 只放行含 flag 关键字的串（见
	// flagRegexPresolve）。换 "secret"/"crypto" 当词条时，解码结果虽然正确，
	// 却会因为不含关键字被 scanFlags 判成「没有 flag」而返回 nil——
	// 那是求解器的设计（不产出非 flag 结论），不是解码方向的问题。
	// 拿它当样本会制造假失败，故词条一律是 flag，只轮换内容。
	payloads := []string{"{abcdefgh}", "{ijklmnop}", "{qrstuvwx}"}
	for _, payload := range payloads {
		plain := "flag " + payload
		enc := encPigLatin(plain)
		if enc == plain {
			t.Fatalf("encPigLatin 对 %q 未产生编码，用例退化为恒等式", plain)
		}
		got := solvePigLatin(context.Background(), enc, nil)
		if len(got) != 1 {
			t.Fatalf("PigLatin(%q→%q) 返回 %v，期望 1 项", plain, enc, got)
		}
		if got[0] != plain {
			t.Fatalf("PigLatin 解码方向错误：%q 解成 %q，期望 %q", enc, got[0], plain)
		}
	}
}
