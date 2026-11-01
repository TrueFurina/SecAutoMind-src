package ctfplatform

// presolve_halfprime_test.go —— 破碎素数求解器测试（2026-10-26）。
// 端到端夹具：真实 partial_tenacity 材料（n/ct 公开于采源附件 output.txt，
// 为题面输入而非答案；解密结果不回显明文，仅比对锚 sha256 前缀）。

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const tenacityText = `n = 118641897764566817417551054135914458085151243893181692085585606712347004549784923154978949512746946759125187896834583143236980760760749398862405478042140850200893707709475167551056980474794729592748211827841494511437980466936302569013868048998752111754493558258605042130232239629213049847684412075111663446003
ct = 7f33a035c6390508cee1d0277f4712bf01a01a46677233f16387fae072d07bdee4f535b0bd66efa4f2475dc8515696cbc4bc2280c20c93726212695d770b0a8295e2bacbd6b59487b329cc36a5516567b948fed368bf02c50a39e6549312dc6badfef84d4e30494e9ef0a47bd97305639c875b16306fcd91146d3d126c1ea476
p = 151441473357136152985216980397525591305875094288738820699069271674022167902643
q = 15624342005774166525024608067426557093567392652723175301615422384508274269305`

func TestHalfPrimeMaterialDetection(t *testing.T) {
	pH := extractLabeledDecimal(tenacityText, "p")
	qH := extractLabeledDecimal(tenacityText, "q")
	if len(pH) != 78 || len(qH) != 77 {
		t.Fatalf("半串提取: p=%d q=%d (期望 78/77)", len(pH), len(qH))
	}
	if len(pH) != len(qH)+1 {
		t.Fatal("范式签名（长度差1）识别失败")
	}
}

func TestKnownDigitsAlignment(t *testing.T) {
	// Lp=155: p_half[0] 是最高位（高位序 0）→ 低位 154
	pK := knownDigits("151441473357136152985216980397525591305875094288738820699069271674022167902643", 155, 0)
	if pK[154] != 1 {
		t.Fatalf("p 最高位对齐错: %v", pK[154])
	}
	if pK[0] != 3 { // 个位 = p_half 最后一位（高位序 154 → 低位 0）
		t.Fatalf("p 个位对齐错: %v", pK[0])
	}
}

func TestHalfPrimeE2EPartialTenacity(t *testing.T) {
	flags := tryHalfPrimeOAEP(tenacityText)
	if len(flags) == 0 {
		t.Fatal("端到端恢复+解密失败")
	}
	// 锚验证（不回显明文）
	sum := sha256.Sum256([]byte(flags[0]))
	got := hex.EncodeToString(sum[:])
	if !strings.HasPrefix(got, "0b5ad12b5ea7f63b") {
		t.Fatalf("锚不匹配: %s", got[:16])
	}
}
