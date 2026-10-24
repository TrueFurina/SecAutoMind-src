package ctfplatform

// presolve_hastad_dedup_test.go —— Håstad 附件重复拼接去重回归（2026-10-24 修）。
//
// 触发链：调用方把附件内容拼进 text 且同时传 attachments map（生产 chat_uploads
// 路径 / crossbench 二进制子集）→ tryHastadBroadcastAttack 内部 fullText 重复拼接
// → 裸数字配对产生重复 (n,c) 对 → 重复 n 不互素 → hastadCRT nil → 真解被吞。
// 实锤题：real_crypto_ezrsa（真实 e=17，3 组 n/c，task.py 不印 e）。
//
// 夹具用 cross_bench 真题数据（与 TestCrossBench 同依赖，缺失则 Skip）——
// 合成小素数无法同时满足 m^e < ∏n 与 flag 外形两个约束，真题是唯一忠实夹具。

import (
	"testing"
)

func TestHastadDedupRepeatedAttachment(t *testing.T) {
	doc := loadCrossBench(t)
	p, ok := doc.Problems["real_crypto_ezrsa"]
	if !ok {
		t.Skip("cross_bench 缺 real_crypto_ezrsa（先跑 scripts/build_cross_bench.py）")
	}
	att, _, _ := loadCrossBenchAttachments(p, false)
	text := p.Description + att // text 已含附件全文
	// 双拼：text 内联 + map 再传（复刻生产 chat_uploads / 二进制子集形态）
	got := tryHastadBroadcastAttack(text, map[string]string{"output": att, "task.py": att})
	if len(got) == 0 {
		t.Fatal("附件双拼场景解不出（重复 n 未去重 → CRT nil 复发）")
	}
	// 单拼对照
	if got2 := tryHastadBroadcastAttack(text, nil); len(got2) == 0 {
		t.Fatal("单拼对照解不出——夹具或环境有误")
	}
}
