package ctfplatform

// presolve_specialcurve2_test.go —— specialcurve2 真实实例端到端回归（A 类要件）。
//
// 实例真值来自公开 writeup（ljahum 博客 2021-12-14，与 verify_specialcurve2.py
// 同源）；flag 官方锚 = flag_sha256（real_crypto_specialcurve2.json）。本测试钉住：
// Go 数学层（复数乘法群快速幂 + ord=∏(p²−1) + ModInverse）从公开参数算出 flag，
// sha256 与官方真值严格闭环——**非合成口径**。
//
// 🔴 实例值不在 93 题库 bench 文本里（附件是脚本模板，随机实例未留存，见附件头
// provenance 注）；本测试按原赛分布形态构造题面（含 n/HINT/C），诚实标注来源。

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const specialCurve2Text = `西湖论剑2021 SpecialCurve2
在复数乘法群（点加定义 x3=x1*x2-y1*y2, y3=x1*y2+x2*y1）上进行类 RSA 加密。
n 是三个强素数乘积（p=2q+1），G=(1,1)，HINT=mul(G,e)，明文 M=(x,y)（flag 拆两半），C=mul(M,e)。
n=92916331959725072239888159454032910975918656644816711315436128106147081837990823
HINT=(1225348982571480649501200428324593233958863708041772597837722864848672736148168, 1225348982571480649501200428324593233958863708041772597837722864848672736148168)
C=(44449540438169324776115009805536158060439126505148790545560105884100348391877176, 73284708680726118305136396988078557189299357177640330968917927635171441710392723)
`

const specialCurve2FlagSHA256 = "cd7e815f4a5a378b8a856ee518a1d7277f306221ce6d68d56dd6f27da2571c4f"

func TestSpecialCurve2RealInstance(t *testing.T) {
	flags := trySpecialCurve2(specialCurve2Text, nil)
	if len(flags) == 0 {
		t.Fatalf("specialcurve2 链未命中（触发/解析/自验任一环断）")
	}
	found := false
	for _, f := range flags {
		if !strings.HasPrefix(f, "DASCTF{") {
			continue
		}
		sum := sha256.Sum256([]byte(f))
		if hex.EncodeToString(sum[:]) == specialCurve2FlagSHA256 {
			found = true
		}
	}
	if !found {
		t.Fatalf("specialcurve2 候选未过官方 sha256 锚（候选数 %d）——数学层或实例解析有误", len(flags))
	}
}
