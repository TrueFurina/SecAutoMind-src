package ctfplatform

import (
	"strings"
	"testing"
)

// P1-1 攻击向量编排层测试。
// 核心要锁的两件事：
//   ① 假设必须**来自本题线索**（不是通用类型目录）；
//   ② 排序看线索强度，且输出稳定可复现（同输入必同序）。

func TestBuildAttackHypothesesFromDescription(t *testing.T) {
	desc := "登录接口 POST /login.php 存在 SQL 注入，参数 user 和 pass 直接拼进 SQL。"
	hints := ParseWebHints(desc)
	if len(hints.Types) == 0 {
		t.Fatalf("题面含 'SQL' 却没解析出类型，ParseWebHints 失效")
	}
	hs := BuildAttackHypotheses(desc, hints)
	if len(hs) == 0 {
		t.Fatalf("应产出攻击假设")
	}
	top := hs[0]
	if top.AttackType != "sqli" {
		t.Fatalf("最强假设应为 sqli，实际 %s", top.AttackType)
	}
	if top.Endpoint != "/login.php" {
		t.Fatalf("端点应来自题面 /login.php，实际 %q", top.Endpoint)
	}
	if top.Method != "POST" {
		t.Fatalf("方法应识别为 POST，实际 %q", top.Method)
	}
	if len(top.Params) == 0 {
		t.Fatalf("应带上题面参数（user/pass）")
	}
	if len(top.Preconditions) == 0 || top.Approach == "" || top.Verify == "" {
		t.Fatalf("前提/构造/验证三要素缺一不可：%+v", top)
	}
}

// 无线索 → 不给假设。宁缺勿猜：把模型导向"没有假设也要打"等于鼓励盲扫。
func TestBuildAttackHypothesesNilWhenNoClue(t *testing.T) {
	if hs := BuildAttackHypotheses("", WebHints{}); hs != nil {
		t.Fatalf("空描述不得产出假设：%+v", hs)
	}
	desc := "这是一个普通的misc题目，没有任何提示。"
	if hs := BuildAttackHypotheses(desc, ParseWebHints(desc)); len(hs) != 0 {
		t.Fatalf("无线索时不得产出假设，实际 %+v", hs)
	}
}

// 多类型命中的排序：线索越多越靠前；同分按类型字典序（稳定可复现）。
func TestAttackHypothesesOrderingIsStable(t *testing.T) {
	desc := "GET /page?file=../../etc/passwd 文件包含；另外 POST /cmd.php?ip=127.0.0.1;cat /flag 命令注入。"
	hints := ParseWebHints(desc)
	hs := BuildAttackHypotheses(desc, hints)
	if len(hs) < 2 {
		t.Fatalf("应产出至少 2 条假设，实际 %d", len(hs))
	}
	for i := 1; i < len(hs); i++ {
		if hs[i-1].Signals < hs[i].Signals {
			t.Fatalf("排序未按线索强度降序：%+v", hs)
		}
		if hs[i-1].Signals == hs[i].Signals && hs[i-1].AttackType > hs[i].AttackType {
			t.Fatalf("同分未按字典序（输出不稳定）：%+v", hs)
		}
	}
	// 同一输入连续两次必须完全一致（防 map 遍历抖动）
	again := BuildAttackHypotheses(desc, ParseWebHints(desc))
	if len(again) != len(hs) {
		t.Fatalf("重复调用结果长度不一致：%d vs %d", len(again), len(hs))
	}
	for i := range again {
		if again[i].AttackType != hs[i].AttackType || again[i].Signals != hs[i].Signals {
			t.Fatalf("重复调用结果不一致：%+v vs %+v", again[i], hs[i])
		}
	}
}

// 未登记的类型不得编造假设（没把握就不给）。
func TestUnknownTypeNotHypothesized(t *testing.T) {
	hs := BuildAttackHypotheses("x", WebHints{Types: []string{"totally_unknown_type"}})
	if len(hs) != 0 {
		t.Fatalf("未登记类型不得产出假设：%+v", hs)
	}
}

// 渲染：必须带线索条数、参数、前提、构造、验证；且**不得含真 flag 或成品 exploit**。
func TestRenderAttackHypothesesNoPlaintextAnswer(t *testing.T) {
	desc := "POST /login.php SQL 注入，参数 user。"
	hints := ParseWebHints(desc)
	hs := BuildAttackHypotheses(desc, hints)
	out := RenderAttackHypotheses(hs)
	if out == "" {
		t.Fatalf("渲染结果不得为空")
	}
	for _, want := range []string{"攻击假设", "前提", "构造", "验证", "线索"} {
		if !strings.Contains(out, want) {
			t.Fatalf("渲染缺关键字段 %q：%s", want, out)
		}
	}
	if strings.Contains(out, "flag{") {
		t.Fatalf("假设块不得含任何 flag 明文：%s", out)
	}
	// 假想：渲染块里不应出现可直接照抄的成品 payload（只给方法）
	if strings.Contains(out, "OR 1=1-- ") && strings.Contains(out, "curl ") {
		t.Fatalf("疑似出现成品 exploit：%s", out)
	}
}

// 排序要"有意义"，前提是各假设的线索数确实不同 —— 初版正是这里退化成全同分，
// 导致排序被架空（变异测试发现的）。本例直接锁住"分数必须分化"。
func TestAttackHypothesesSignalsDifferAcrossTypes(t *testing.T) {
	desc := "站点有 /cmd.php?ip=127.0.0.1;cat /flag 命令注入，另说登录处 user 参数疑似 SQL。"
	hints := ParseWebHints(desc)
	hs := BuildAttackHypotheses(desc, hints)
	if len(hs) < 2 {
		t.Skipf("本描述只解析出 %d 类，无法验证分数分化", len(hs))
	}
	seen := map[int]bool{}
	for _, h := range hs {
		seen[h.Signals] = true
	}
	if len(seen) < 2 {
		t.Fatalf("各假设线索数应当分化（否则排序无意义），实际：%+v", hs)
	}
}
