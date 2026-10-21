package ctfplatform

// web_hints_test.go —— 「读题取线索 → 定向打靶」能力机验。
//
// 对照实验设计（这是本测试的核心价值）：
//   A 组（无线索）：ExploitWebTarget  —— 只靠硬编码端点猜
//   B 组（有线索）：ExploitWebTargetWithHints(ParseWebHints(题目描述))
//   C 组（生产入口）：ExploitURLsInText —— 线上真实调用路径
// 靶场的端点（/cmd.php、/index.php、/profile、/fetch.php、/login.php、/api/auth）
// 刻意避开硬编码列表，B 组（读题定向）必须打得中。
//
// ⚠️ 跨语言 parity 口径（2026-10-16 接线，见 parity_registry.json【5】）：
//   跨语言互证的对象是 **B 组逐题命中集**（两侧各打印 `✅ HIT <pid>`，门禁比对），
//   实测两侧均 6/6 一致。**A 组（无线索基线）两侧实现口径不同**——Go 侧走
//   ExploitWebTarget 的硬编码端点猜测（实测 4/6），Python 侧走 parse_hints("")
//   的「首页爬链 + 全类型回退」（实测 3/6）——故 **「增量」数字不跨语言互证**，
//   只在各侧内部作对照。本测试对 A 组只要求「增量严格为正」（fail-closed），
//   不再假设 A 组两侧相等（此前的「A/B/C 三组一致」是对外失真宣称，已被本接线证伪）。
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

type hintBenchProblem struct {
	FlagSHA256  string `json:"flag_sha256"`
	Description string `json:"description"`
}

func loadHintBenchmark(t *testing.T) map[string]hintBenchProblem {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "data", "ctf_benchmark", "web_hint_benchmark.json"))
	if err != nil {
		t.Skip("web_hint_benchmark.json 缺失（先跑 web_range_hints.py --dump-json），跳过")
	}
	var doc struct {
		Problems map[string]hintBenchProblem `json:"problems"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析线索基准集失败: %v", err)
	}
	return doc.Problems
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestHintDrivenWebExploit A/B/C 三组对照机验。
func TestHintDrivenWebExploit(t *testing.T) {
	root := filepath.Join("..", "..")
	rangePy := filepath.Join(root, "data", "ctf_benchmark", "live_target", "web_range_hints.py")
	if _, err := os.Stat(rangePy); err != nil {
		t.Skip("线索靶场脚本缺失，跳过")
	}
	probs := loadHintBenchmark(t)

	port := "18099"
	cmd := exec.Command("python", rangePy, port)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动线索靶场失败: %v", err)
	}
	defer func() { killProcessTree(cmd.Process.Pid) }()

	baseURL := "http://127.0.0.1:" + port
	ready := false
	for i := 0; i < 80; i++ {
		if resp, err := http.Get(baseURL + "/"); err == nil {
			resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("线索靶场未就绪")
	}

	ids := make([]string, 0, len(probs))
	for id := range probs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	hitOf := func(findings []WebFinding, want string) bool {
		for _, f := range findings {
			if f.Flag != "" && sha256Hex(f.Flag) == want {
				return true
			}
		}
		return false
	}

	noHint, withHint, viaText := 0, 0, 0
	for _, id := range ids {
		p := probs[id]
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

		// A 组：无线索（硬编码端点猜测）
		if hitOf(ExploitWebTarget(ctx, baseURL), p.FlagSHA256) {
			noHint++
		}
		// B 组：读题取线索后定向打
		hints := ParseWebHints(p.Description)
		okB := hitOf(ExploitWebTargetWithHints(ctx, baseURL, hints), p.FlagSHA256)
		if okB {
			withHint++
			t.Logf("✅ HIT  %s", id) // 逐题机验口径，与 suite_parity_test.go 同构
		} else {
			t.Errorf("❌ %-12s 有线索仍未命中（端点=%v 参数=%v 类型=%v）",
				id, hints.Endpoints, hints.Params, hints.Types)
		}
		// C 组：生产入口（题目文本里带靶机地址）
		text := "题目描述: " + p.Description + "\n靶机: " + baseURL
		if out := ExploitURLsInText(ctx, text); len(out) > 0 {
			found := false
			for _, f := range out {
				if sha256Hex(f) == p.FlagSHA256 {
					found = true
				}
			}
			if found {
				viaText++
			} else {
				t.Errorf("❌ %-12s 生产入口 ExploitURLsInText 未命中", id)
			}
		} else {
			t.Errorf("❌ %-12s 生产入口 ExploitURLsInText 无输出", id)
		}
		cancel()
	}

	// fail-closed：有线索必须**严格优于**无线索，否则「能力增量」主张失效。
	// 此前 A 组只计数、不断言——若硬编码探测哪天恰好命中靶场端点致增量归零，
	// 本测试照样绿（同族空洞绿：判据边界恒真）。
	if withHint <= noHint {
		t.Errorf("❌ 对照基线失效：无线索 %d >= 有线索 %d，线索增量非正（A/B 对照设计已失效）",
			noHint, withHint)
	}

	t.Logf("=== 线索定向渗透对照（靶场端点均不在硬编码列表）===")
	t.Logf("    A 组 无线索（硬编码猜测）: %d/%d", noHint, len(ids))
	t.Logf("    B 组 读题取线索定向打  : %d/%d", withHint, len(ids))
	t.Logf("    C 组 生产入口带文本    : %d/%d", viaText, len(ids))
	t.Logf("    能力增量: +%d 题（%.0f%% → %.0f%%）",
		withHint-noHint,
		float64(noHint)*100/float64(len(ids)),
		float64(withHint)*100/float64(len(ids)))
}

// TestParseWebHintsOffline 线索解析纯离线单测（不发任何网络请求）。
func TestParseWebHintsOffline(t *testing.T) {
	cases := []struct {
		text       string
		wantEndp   string
		wantParam  string
		wantTypeOf string
	}{
		{"GET /cmd.php?ip=127.0.0.1;cat /flag 命令注入读取 flag", "/cmd.php", "ip", "cmdi"},
		{"GET /index.php?page=../../../../etc/passwd 本地文件包含", "/index.php", "page", "lfi"},
		{"POST /login.php user=admin' OR 1=1--&pass=x SQL 注入绕过登录", "/login.php", "user", "sqli"},
		{"SSTI 模板注入：输入 {{7*7}} 返回 49（参数名 name）", "", "name", "ssti"},
	}
	for _, c := range cases {
		h := ParseWebHints(c.text)
		if c.wantEndp != "" {
			found := false
			for _, e := range h.Endpoints {
				if e == c.wantEndp {
					found = true
				}
			}
			if !found {
				t.Errorf("端点解析失败 %q: 得到 %v", c.text, h.Endpoints)
			}
		}
		if c.wantParam != "" {
			found := false
			for _, p := range h.Params {
				if p == c.wantParam {
					found = true
				}
			}
			if !found {
				t.Errorf("参数解析失败 %q: 得到 %v", c.text, h.Params)
			}
		}
		if !hintsHaveType(h, c.wantTypeOf) {
			t.Errorf("类型判定失败 %q: 得到 %v", c.text, h.Types)
		}
	}
}
