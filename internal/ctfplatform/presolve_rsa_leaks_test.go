// presolve_rsa_leaks_test.go —— rsa_phi_pinv / legendre_bit_phi / hastad 裸数字
// 三条攻击的回归测试（2026-10-15 cross-bench 立尺驱动）。
//
// 纪律（与本仓门禁约定一致）：每个攻击配 ①合成 fixture 正向回归 ②变异用例
// （输入损坏必须 fail-closed 返回 nil，不许为了转绿放松判据）。
// 固定素数离线生成（seed 20261015），fixture 在测试内程序化构建，跨平台确定性。

package ctfplatform

import (
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"testing"
)

// ── rsa_phi_pinv（玄盾杯 ExcitingInverse 型：已知 phi+pinv/qinv，n 未给出） ──

const (
	// 160-bit 素数（49 位十进制 ≥40 位门槛；n≈320-bit，pinv/qinv≈160-bit，
	// 位长间隙 160 ≥ 128 聚类阈值）。
	phiPinvP = "1017657164761435080805545366079386910285931309771"
	phiPinvQ = "1373078902225174476147900606716923679368701945749"
)

// buildPhiPinvFixture 按真题形态构建题面：e 独占首行，随后 phi, c, pinv, qinv 裸行。
// corrupt 非空时损坏对应字段（变异用例）："phi"→phi+2，"c"→c+1，"pinv"→pinv+2。
func buildPhiPinvFixture(t *testing.T, flag, corrupt string) string {
	t.Helper()
	p, ok1 := new(big.Int).SetString(phiPinvP, 10)
	q, ok2 := new(big.Int).SetString(phiPinvQ, 10)
	if !ok1 || !ok2 {
		t.Fatalf("固定素数解析失败")
	}
	one := big.NewInt(1)
	e := big.NewInt(65537)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	n := new(big.Int).Mul(p, q)
	pinv := new(big.Int).ModInverse(p, q) // p^{-1} mod q
	qinv := new(big.Int).ModInverse(q, p) // q^{-1} mod p
	m := new(big.Int).SetBytes([]byte(flag))
	c := new(big.Int).Exp(m, e, n)
	switch corrupt {
	case "phi":
		phi.Add(phi, big.NewInt(2))
	case "c":
		c.Add(c, big.NewInt(1))
	case "pinv":
		pinv.Add(pinv, big.NewInt(2))
	}
	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n", e, phi, c, pinv, qinv)
}

func TestRSAPhiPinvSynthetic(t *testing.T) {
	const flag = "flag{PHI_PINV_SYNTH_2026}"
	got := tryRSAPhiPinv(buildPhiPinvFixture(t, flag, ""))
	if len(got) == 0 || got[0] != flag {
		t.Fatalf("rsa_phi_pinv 合成用例失手：got=%v want=%q", got, flag)
	}
}

func TestRSAPhiPinvMutationFailClosed(t *testing.T) {
	// 任一关键字段损坏 → 二次方程无整数根或 (p-1)(q-1)≠phi 校验失败 → 必须 nil。
	for _, corrupt := range []string{"phi", "c", "pinv"} {
		got := tryRSAPhiPinv(buildPhiPinvFixture(t, "flag{PHI_PINV_SYNTH_2026}", corrupt))
		if len(got) != 0 {
			t.Errorf("损坏字段 %q 后应 fail-closed，实际返回 %v", corrupt, got)
		}
	}
	// 数字不足 4 个 → 直接 nil（守卫分支）。
	if got := tryRSAPhiPinv("1234567890123456789012345678901234567890\n"); len(got) != 0 {
		t.Errorf("数字不足应返回 nil，实际 %v", got)
	}
}

// ── legendre_bit_phi（玄盾杯 SimpleLegendre 型：phi 泄露 + 逐位 Legendre 加密） ──

const (
	// 136-bit 素数 → N≈272-bit（≥256 门槛），密文≈82 位十进制（≥40 门槛）。
	legendreP = "54717620234706130792572180241834563619729"
	legendreQ = "46691102830131948325680809883655251852901"
)

// buildLegendreFixture 按真题 task.py 语义构建：phi、N 各一行，随后每比特一个密文
// c_i = x^(2·r+bi)·r² mod N（指数 int(br+bi,2)=2r+bi），比特 MSB 优先。
// truncateBits>0 时只输出前 N 个比特的密文（变异用例：密文不完整）。
func buildLegendreFixture(t *testing.T, flag string, truncateBits int) string {
	t.Helper()
	p, ok1 := new(big.Int).SetString(legendreP, 10)
	q, ok2 := new(big.Int).SetString(legendreQ, 10)
	if !ok1 || !ok2 {
		t.Fatalf("固定素数解析失败")
	}
	one := big.NewInt(1)
	N := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	// x：(x|p)=(x|q)=−1（欧拉判别法试搜；固定 seed 保证确定性）。
	// math/big 无 Jacobi，用定义式 a^((p-1)/2) mod p：1→+1，p-1→−1，0→0。
	fixtureLegendre := func(a, p *big.Int) int {
		r := new(big.Int).Exp(a, new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1), p)
		switch {
		case r.Sign() == 0:
			return 0
		case r.Cmp(big.NewInt(1)) == 0:
			return 1
		default:
			return -1
		}
	}
	rng := rand.New(rand.NewSource(0x1E6E17E))
	var x *big.Int
	for {
		x = new(big.Int).Rand(rng, N)
		if x.Sign() == 0 {
			continue
		}
		if fixtureLegendre(x, p) == -1 && fixtureLegendre(x, q) == -1 {
			break
		}
	}
	msg := new(big.Int).SetBytes([]byte(flag))
	bits := fmt.Sprintf("%b", msg) // MSB 优先，与 bin(bytes_to_long(msg))[2:] 一致
	if truncateBits > 0 && truncateBits < len(bits) {
		bits = bits[:truncateBits]
	}
	var sb strings.Builder
	sb.WriteString(phi.String() + "\n")
	sb.WriteString(N.String() + "\n")
	for _, ch := range bits {
		bi := uint(ch - '0')
		var r *big.Int
		for {
			r = new(big.Int).Rand(rng, N)
			if r.Sign() > 0 && new(big.Int).GCD(nil, nil, r, N).Cmp(one) == 0 {
				break
			}
		}
		exp := new(big.Int).Lsh(r, 1) // 2r
		if bi == 1 {
			exp.Add(exp, one) // 2r+bi
		}
		c := new(big.Int).Exp(x, exp, N)
		c.Mul(c, new(big.Int).Mul(r, r)) // ·r²
		c.Mod(c, N)
		sb.WriteString(c.String() + "\n")
	}
	return sb.String()
}

func TestLegendreBitPhiSynthetic(t *testing.T) {
	const flag = "flag{LEGENDRE_SYNTH_2026}"
	got := tryLegendreBitPhi(buildLegendreFixture(t, flag, 0))
	if len(got) == 0 || got[0] != flag {
		t.Fatalf("legendre_bit_phi 合成用例失手：got=%v want=%q", got, flag)
	}
}

func TestLegendreBitPhiMutationFailClosed(t *testing.T) {
	const flag = "flag{LEGENDRE_SYNTH_2026}"
	// 变异 1：密文截断（只剩 40 比特 ≈ 5 字节）→ 明文不完整 → 扫不出 flag 外形 → nil。
	if got := tryLegendreBitPhi(buildLegendreFixture(t, flag, 40)); len(got) != 0 {
		t.Errorf("密文截断后应 fail-closed，实际 %v", got)
	}
	// 变异 2：phi 与 N 对调（nums[0]=N, nums[1]=phi）→ factorFromPhi 失败 → nil。
	full := buildLegendreFixture(t, flag, 0)
	lines := strings.Split(strings.TrimSpace(full), "\n")
	lines[0], lines[1] = lines[1], lines[0]
	if got := tryLegendreBitPhi(strings.Join(lines, "\n") + "\n"); len(got) != 0 {
		t.Errorf("phi/N 对调后应 fail-closed，实际 %v", got)
	}
	// 变异 3：数字不足 12 个 → nil（守卫分支）。
	if got := tryLegendreBitPhi("11111111111111111111111111111111111111\n22222222222222222222222222222222222222\n"); len(got) != 0 {
		t.Errorf("数字不足应返回 nil，实际 %v", got)
	}
}

// ── hastad 裸数字格式回归（ezRSA 型：e 不印刷、真实 e=17） ──
//
// 锁死两个已修缺陷（2026-10-15）：
//  1. 指数候选集 {3,5,7,9,11,13} 漏掉 e=17（ezRSA 真实值）；
//  2. hastadRootScan 曾用 e.Sign()<3 判大小（Sign 只返回 -1/0/1，
//     e=17 时 1<3 直接误杀）——本用例 e=17 正向命中即为该 bug 的回归锁。

const (
	// 512-bit 素数 ×6（seed 20261015）：n_i≈1024-bit，∏n≈3072-bit > m^17≈2312-bit，
	// 保证 CRT 合成后 x=m^17 精确成立（攻击前提 m^e<∏n_i）。
	hastadPrime1 = "12987690931351706000825335163530757425722827172252355695783843853428459223193731029219852897578487072558797520993559799823158039016325162043638112883251303"
	hastadPrime2 = "9549463452451133671152944686024442751172559978194534539183804668745352064196266680005919286024001547873980664536996575744101393490372973247097719577382953"
	hastadPrime3 = "10988857324102379083789621304316985454292647492789221260143244012769543557920338101297057335036836847542949267657270640100655201584868446284388558223051143"
	hastadPrime4 = "10912058507521008755169892425486542653657459861325902058447638885775308806198816942912430811511234199262286298560367708190181561654375901449875663003931979"
	hastadPrime5 = "7828368277912527236743720279640096188392685824790302671609859960936079003250316216477892509211623074032504888507305822354607882688449710084150767433089597"
	hastadPrime6 = "12736557315103383415752263484784904630350013867421831290146945365946545201251717032746066350718260363693692767361633183852088061186140676085997804444668573"
)

// buildHastadBareFixture 按 ezRSA output 形态构建：逐行 n1,c1,n2,c2,n3,c3，不印 e。
// corrupt 非空时把第 2 组密文 +1（变异用例）。
func buildHastadBareFixture(t *testing.T, flag string, corrupt bool) string {
	t.Helper()
	primes := []string{hastadPrime1, hastadPrime2, hastadPrime3, hastadPrime4, hastadPrime5, hastadPrime6}
	e := big.NewInt(17) // ezRSA 真实指数（task.py 仅 assert(e<100)，不印刷）
	m := new(big.Int).SetBytes([]byte(flag))
	var sb strings.Builder
	for i := 0; i+1 < len(primes); i += 2 {
		p, ok1 := new(big.Int).SetString(primes[i], 10)
		q, ok2 := new(big.Int).SetString(primes[i+1], 10)
		if !ok1 || !ok2 {
			t.Fatalf("固定素数解析失败")
		}
		n := new(big.Int).Mul(p, q)
		c := new(big.Int).Exp(m, e, n)
		if corrupt && i == 2 {
			c.Add(c, big.NewInt(1))
		}
		sb.WriteString(n.String() + "\n")
		sb.WriteString(c.String() + "\n")
	}
	return sb.String()
}

func TestHastadBareNumbersE17Synthetic(t *testing.T) {
	const flag = "flag{HASTAD_E17_SYNTH}"
	got := tryHastadBroadcastAttack(buildHastadBareFixture(t, flag, false), nil)
	if len(got) == 0 || got[0] != flag {
		t.Fatalf("hastad 裸数字 e=17 合成用例失手：got=%v want=%q", got, flag)
	}
}

func TestHastadBareNumbersMutationFailClosed(t *testing.T) {
	// 任一组密文损坏 → CRT 合成值不再是 17 次完全幂 → 全范围 e 试错均 nil。
	got := tryHastadBroadcastAttack(buildHastadBareFixture(t, "flag{HASTAD_E17_SYNTH}", true), nil)
	if len(got) != 0 {
		t.Errorf("密文损坏后应 fail-closed，实际 %v", got)
	}
	// 少于 3 组 → nil（守卫分支）。
	if got := tryHastadBroadcastAttack("1\n2\n", nil); len(got) != 0 {
		t.Errorf("无数字应返回 nil，实际 %v", got)
	}
}
