package runnerl3

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudwego/eino/schema"
)

// P0-3 硬约束层测试（2026-10-26）。
// 验收口径来自计划原文：**LLM 输出引用不存在的文件路径时，编排层必须打回而非放行**。

func TestValidateToolCall(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args map[string]any
		want bool // true=通过校验
	}{
		{"execute_python 合法", "execute_python", map[string]any{"skill_name": "xor_bruteforce"}, true},
		{"execute_python 带 params", "execute_python", map[string]any{"skill_name": "ctf_sage_t1_coppersmith", "params": "{\"modulus\":1}"}, true},
		{"execute_python 缺 skill_name", "execute_python", map[string]any{"params": "{}"}, false},
		{"execute_python skill_name 空串", "execute_python", map[string]any{"skill_name": "  "}, false},
		{"execute_python skill_name 非字符串", "execute_python", map[string]any{"skill_name": 123}, false},
		{"execute_python 未知参数", "execute_python", map[string]any{"skill_name": "x", "code": "print(1)"}, false},
		{"read_attachment 合法", "read_attachment", map[string]any{"attachment_url": "http://x/y.txt"}, true},
		{"read_attachment 缺参数", "read_attachment", map[string]any{}, false},
		{"read_attachment 未知参数", "read_attachment", map[string]any{"attachment_url": "http://x", "path": "/tmp/a"}, false},
		{"未知工具名", "run_shell", map[string]any{"cmd": "ls"}, false},
		{"空工具名", "", map[string]any{}, false},
	}
	for _, c := range cases {
		err := validateToolCall(c.tool, c.args)
		if (err == nil) != c.want {
			t.Errorf("%s: validateToolCall err=%v, want pass=%v", c.name, err, c.want)
		}
	}
}

// 变异防护：若将来有人把 execute_python 的必填参数删掉，本测试必须红。
func TestToolSchemasRegistryIntegrity(t *testing.T) {
	py, ok := toolSchemas["execute_python"]
	if !ok {
		t.Fatal("execute_python 必须登记 schema")
	}
	if len(py.required) == 0 || py.required[0] != "skill_name" {
		t.Fatalf("execute_python 必填参数应为 skill_name，实际 %v", py.required)
	}
	att, ok := toolSchemas["read_attachment"]
	if !ok {
		t.Fatal("read_attachment 必须登记 schema")
	}
	if len(att.required) == 0 || att.required[0] != "attachment_url" {
		t.Fatalf("read_attachment 必填参数应为 attachment_url，实际 %v", att.required)
	}
}

func TestFactLedgerRecordsAttachmentPath(t *testing.T) {
	l := newFactLedger()
	const p = "/tmp/secautomind_att_flag.txt"
	result := fmt.Sprintf("附件下载成功:\n路径: %s\n大小: 12 bytes\nMIME: text/plain\n--- strings 前 80 行 ---\nflag{x}", p)
	l.recordFactsFromToolResult("read_attachment", result)
	if !l.has(p) {
		t.Fatalf("工具返回里的真实路径必须入账：%v", l.files)
	}
	if l.count() != 1 {
		t.Fatalf("事实数应为 1，实际 %d", l.count())
	}
	// 失败返回不得凭空造事实
	l2 := newFactLedger()
	l2.recordFactsFromToolResult("read_attachment", "[read_attachment HTTP 404] url=x")
	if l2.count() != 0 {
		t.Fatalf("失败返回不得记录事实，实际 %d", l2.count())
	}
}

func TestExtractUnbackedFileClaims(t *testing.T) {
	l := newFactLedger()
	l.addFile("/tmp/real/attachment.txt")

	cases := []struct {
		name string
		text string
		want int
	}{
		{"无声称动词则不算幻觉", "/tmp/fake/a.txt 里有个 flag{x}", 0},
		{"声称读取未记录路径", "我读取了 /tmp/fake/a.txt，得到 flag{x}", 1},
		{"声称读取已记录路径", "我读取了 /tmp/real/attachment.txt，得到 flag{x}", 0},
		{"单段路径不判幻觉（保守）", "我读取了 /etc/passwd", 0},
		{"系统目录路径不判幻觉（防误杀 flag 正文）", "我读取了 /usr/local/bin/xx，得到 flag{x}", 0},
		{"临时目录下 2 段路径仍判幻觉", "我读取了 /tmp/ghost.txt，得到 flag{x}", 1},
		{"英文声称动词同样生效", "I opened /tmp/ghost/b.bin and got flag{x}", 1},
		{"无路径", "我读取了附件，得到 flag{x}", 0},
		{"多行各自判定", "无关行\n我下载了 /tmp/g1/c.txt\n我打开了 /tmp/real/attachment.txt", 1},
	}
	for _, c := range cases {
		got := extractUnbackedFileClaims(c.text, l)
		if len(got) != c.want {
			t.Errorf("%s: 命中 %d 条 %v，want %d", c.name, len(got), got, c.want)
		}
	}
}

// 验收用例：模型声称打开了一个从未被工具产生过的文件 → 编排层打回（不返回候选）。
func TestSolveRejectsHallucinatedFileClaim(t *testing.T) {
	m := &fakeModel{resps: []*schema.Message{
		textResp("我打开了 /tmp/nonexistent_dir/secret.txt，里面写着 flag{hallucinated_flag}"),
	}}
	ff := newTestFallback(m, 12, 12)

	flags, err := ff.Solve(context.Background(), testChallenge())
	if err != nil {
		t.Fatalf("打回应走无产出路径，不该报错: %v", err)
	}
	if flags != nil {
		t.Fatalf("幻觉文件路径必须被打回，实际返回 %v", flags)
	}
}

// 反向验证：路径确实由工具产生（有工具记录）时**不得误杀** —— 否则闸门会砍掉真答案。
func TestSolveAllowsBackedFileClaim(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ATTACH\nflag{real_backed_flag}\nEND")
	}))
	defer srv.Close()

	realPath := filepath.Join(os.TempDir(), "secautomind_att_flag.txt")

	m := &fakeModel{resps: []*schema.Message{
		toolResp("read_attachment", fmt.Sprintf(`{"attachment_url": %q}`, srv.URL+"/flag.txt")),
		textResp(fmt.Sprintf("我读取了 %s，得到 flag{real_backed_flag}", realPath)),
	}}
	ff := newTestFallback(m, 12, 12)

	flags, err := ff.Solve(context.Background(), testChallenge())
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if len(flags) == 0 {
		t.Fatalf("真实路径有工具记录，不得被闸门误杀（返回空）")
	}
}

// ① 的端到端：模型瞎加 schema 外的参数 → 变成工具错误步，不执行、不静默忽略。
func TestExecuteToolRejectsUnknownParam(t *testing.T) {
	ff := newTestFallback(&fakeModel{}, 2, 2)
	got := ff.executeTool(context.Background(), schema.ToolCall{
		ID: "c1",
		Function: schema.FunctionCall{
			Name:      "read_attachment",
			Arguments: `{"attachment_url":"http://x/y","extra":"zzz"}`,
		},
	}, testChallenge(), newFactLedger())

	if !isToolError(got) {
		t.Fatalf("非法参数必须判为工具错误步（供监督计数），实际 %q", got)
	}
	if !contains(got, "参数校验失败") {
		t.Fatalf("应回参数校验失败，实际 %q", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(sub) > 0 && indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
