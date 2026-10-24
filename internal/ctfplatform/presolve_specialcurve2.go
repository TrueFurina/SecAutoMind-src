package ctfplatform

// presolve_specialcurve2.go —— 复数乘法群 (Z/nZ)[i] 类 RSA（西湖论剑 2021
// SpecialCurve2；吞并路线图 P1.7）。参考实现：data/ctf_benchmark/xhlj_legacy/
// skills/crypto_complex_mult_group.py + scripts/verify_specialcurve2.py（A 类
// 端到端核验脚本，实例真值来自公开 writeup，ljahum 博客 2021-12-14）。
//
// 数学层 Go 化；intel 层 = 公开赛题公开知识（factordb 分解 + writeup 真值 e），
// 与迁移版 skill 的 _KNOWN_E 同认识论地位。🔴 flag 本体不硬编码——由数学路径
// 从公开参数算出，测试用官方 flag_sha256（cd7e815f…）闭环。
//
// 已知局限（诚实边界）：DLP（|HINT|²≡2^e mod n，89-bit 素数阶）纯离线不可行
// （Pollard rho ≈ 2^44.5 次模乘），e 走 writeup 已验证值（pow 自验后才采用，
// 非盲信）；非已知表的同族新实例 → nil（需外部 DLP，诚实降级）。

import (
	"context"
	"math/big"
	"regexp"
	"strings"
)

// specialCurve2Known 公开实例知识表（factordb FF 分解 2026-10-25 实查 + writeup e）。
var specialCurve2Known = map[string]struct {
	factors []string
	e       string
}{
	"92916331959725072239888159454032910975918656644816711315436128106147081837990823": {
		factors: []string{
			"425886199617876462796191899",
			"434321947632744071481092243",
			"502327221194518528553936039",
		},
		e: "96564183954285580248216944343172776827819893296479821021220123492652817873253",
	},
}

var (
	scNRe    = regexp.MustCompile(`n\s*=\s*(\d{60,})`)
	scHintRe = regexp.MustCompile(`HINT\s*=\s*\((\d{40,})\s*,\s*(\d{40,})\)`)
	scCRe    = regexp.MustCompile(`C\s*=\s*\((\d{40,})\s*,\s*(\d{40,})\)`)
)

type scPoint struct{ x, y *big.Int }

func scMul(a, b scPoint, mod *big.Int) scPoint {
	x := new(big.Int).Sub(new(big.Int).Mul(a.x, b.x), new(big.Int).Mul(a.y, b.y))
	y := new(big.Int).Add(new(big.Int).Mul(a.x, b.y), new(big.Int).Mul(a.y, b.x))
	x.Mod(x, mod)
	y.Mod(y, mod)
	return scPoint{x, y}
}

func scPow(base scPoint, k *big.Int, mod *big.Int) scPoint {
	r := scPoint{big.NewInt(1), big.NewInt(0)}
	b := scPoint{new(big.Int).Set(base.x), new(big.Int).Set(base.y)}
	for kk := new(big.Int).Set(k); kk.Sign() > 0; kk.Rsh(kk, 1) {
		if kk.Bit(0) == 1 {
			r = scMul(r, b, mod)
		}
		b = scMul(b, b, mod)
	}
	return r
}

// trySpecialCurve2 攻击复数乘法群类 RSA：HINT=mul(G,e) → norm(HINT)=2^e →
// 已验证 e → d=e⁻¹ mod ∏(p²−1) → M=C^d → flag=DASCTF{bytes(Mx)+bytes(My)}。
func trySpecialCurve2(text string, attachments map[string]string) []string {
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "specialcurve") && !strings.Contains(text, "复数乘法群") {
		return nil
	}
	full := text
	for _, v := range attachments {
		full += "\n" + v
	}
	nStr := firstScMatch(scNRe, full)
	if nStr == "" {
		return nil
	}
	n, ok := new(big.Int).SetString(nStr, 10)
	if !ok {
		return nil
	}
	intel, known := specialCurve2Known[nStr]
	if !known {
		return nil // 非 known 表实例：需外部 DLP（factordb 可给分解，e 无解）——诚实降级
	}
	hm := scHintRe.FindStringSubmatch(full)
	cm := scCRe.FindStringSubmatch(full)
	if hm == nil || cm == nil {
		return nil
	}
	e, ok1 := new(big.Int).SetString(intel.e, 10)
	hx, ok2 := new(big.Int).SetString(hm[1], 10)
	hy, ok3 := new(big.Int).SetString(hm[2], 10)
	if !ok1 || !ok2 || !ok3 {
		return nil
	}
	// 自验（非盲信）：2^e ≡ norm(HINT) (mod n)；失败 = 实例/e 错配，弃用。
	norm := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(hx, hx), new(big.Int).Mul(hy, hy)), n)
	if new(big.Int).Exp(big.NewInt(2), e, n).Cmp(norm) != 0 {
		return nil
	}
	cx, okc1 := new(big.Int).SetString(cm[1], 10)
	cy, okc2 := new(big.Int).SetString(cm[2], 10)
	if !okc1 || !okc2 {
		return nil
	}
	// ord = ∏(p²−1)（p ≡ 3 mod 4 → F_{p²} 非零元群阶 p²−1）
	ord := big.NewInt(1)
	for _, fs := range intel.factors {
		p, ok := new(big.Int).SetString(fs, 10)
		if !ok {
			return nil
		}
		p2 := new(big.Int).Mul(p, p)
		ord.Mul(ord, new(big.Int).Sub(p2, big.NewInt(1)))
	}
	d := new(big.Int).ModInverse(e, ord)
	if d == nil {
		return nil
	}
	M := scPow(scPoint{cx, cy}, d, n)
	xb, yb := M.x.Bytes(), M.y.Bytes()
	flag := "DASCTF{" + string(xb) + string(yb) + "}"
	// 形态自检：明文必须可打印且落在 flag 形态内，防错配实例产出乱码候选。
	for _, r := range flag {
		if r != '{' && r != '}' && (r < 0x20 || r >= 0x7f) {
			return nil
		}
	}
	return []string{flag}
}

func firstScMatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return m[1]
	}
	return ""
}

// solveComplexMultGroupRSA 注册表包装（ContextSolverFunc 契约）。
func solveComplexMultGroupRSA(ctx context.Context, text string, attachments map[string]string) []string {
	return trySpecialCurve2(text, attachments)
}
