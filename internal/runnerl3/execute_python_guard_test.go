package runnerl3

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"
	"testing"
)

// execute_python 的两条绕过（2026-11-01）。
//
// 背景：`python_session` 的路径围栏只管会话进程；`execute_python` 走的是
// cmd/runner 的 pySkillRunner **子进程**，不吃那条围栏。于是有两条不需要
// "攻破"任何东西的正常调用路径：
//   ① skill_name 被拼进 `import <name> as s` ⇒ 带换行即可注入任意 Python；
//   ② params 被原样并进 skill 入参 ⇒ `{"path": "<真值文件>"}` 让 skill 替它读。
//
// 这两个用例断言的是"**桥接层根本没被调用**"，不是"返回了好听的错误文本" ——
// 只断言文本的话，把拦截放到调用之后（照样执行了子进程）也会绿。

// identifierPayload 是真实的注入载荷：拼接后得到
//   import os as s
//   import sys
//   print('INJ'+'ECTED')
//   sys.exit(0)
//   import os as s
// 进程以 0 退出 ⇒ 旧实现会把 'INJECTED …' 当成 skill 成功输出回给模型。
//
// 标记写成 `'INJ'+'ECTED'` 是有意的：拒因文本会把 payload 原样回显给模型
// （便于它自纠），若载荷里直接出现 INJECTED 字样，"回显"与"真跑了"就分不开。
var injectedSkillNameRe = regexp.MustCompile(`INJECTED`)

const injectedPayload = "os as s; import sys; print('INJ'+'ECTED'); sys.exit(0); import os"

func TestExecutePythonRejectsInjectedSkillName(t *testing.T) {
	rich := &fakeRichRunner{richText: "SHOULD_NOT_RUN", richOK: true}
	f := &LLMFallback{pyBridge: rich}

	got := f.toolExecutePython(context.Background(), map[string]any{
		"skill_name": injectedPayload,
	}, richChallenge())

	if rich.calls != 0 {
		t.Fatalf("注入 payload 仍被送进桥接层（calls=%d）—— 拦截发生在执行之后", rich.calls)
	}
	if injectedSkillNameRe.MatchString(got) {
		t.Fatalf("注入代码真的跑了：%q", got)
	}
	if !strings.HasPrefix(got, "[execute_python 拒绝执行]") {
		t.Fatalf("拒因不明确：%q", got)
	}
	if !isToolError(got) {
		t.Fatalf("拒绝必须被监督计为工具错误步（否则规则⑥收口被架空）：%q", got)
	}
}

// 反例：文档里承诺的合法别名必须照常放行（结构校验不能把功能砍掉）。
func TestExecutePythonAllowsDocumentedSkillAliases(t *testing.T) {
	for _, name := range []string{
		"angr_decompile", "zip_crack", "image_steg", "pcap_analyze",
		"ctf_sage_t1_coppersmith", "pwn_ret2libc", "reverse_elf_general",
	} {
		rich := &fakeRichRunner{richText: `{"ok":true}`, richOK: true}
		f := &LLMFallback{pyBridge: rich}
		got := f.toolExecutePython(context.Background(), map[string]any{"skill_name": name}, richChallenge())
		if rich.calls != 1 {
			t.Errorf("合法 skill %q 被拦下了：%q", name, got)
		}
	}
}

// ② 参数夹带路径：越界绝对路径必须挡在调用前。
func TestExecutePythonRejectsOutOfWorkspacePathParam(t *testing.T) {
	rich := &fakeRichRunner{richText: "SHOULD_NOT_RUN", richOK: true}
	f := &LLMFallback{pyBridge: rich}

	got := f.toolExecutePython(context.Background(), map[string]any{
		"skill_name": "zip_crack",
		"params":     `{"path":"/home/user/SecAutoMind/data/ctf_benchmark/real_benchmark.json","wordlist":"rockyou"}`,
	}, richChallenge())

	if rich.calls != 0 {
		t.Fatalf("越界 path 仍被执行（calls=%d）—— 参数围栏没接上", rich.calls)
	}
	if !strings.HasPrefix(got, "[execute_python 拒绝执行]") {
		t.Fatalf("拒因不明确：%q", got)
	}
	if !strings.Contains(got, "real_benchmark.json") {
		t.Fatalf("拒因应点名越界路径，便于模型自纠：%q", got)
	}
}

// 反例一：收件箱里的附件路径必须放行（否则 read_attachment + execute_python 组合被自己废掉）。
func TestExecutePythonAllowsInboxAttachmentPath(t *testing.T) {
	inboxFile := path.Join(attachmentInboxFenceRoot(), "vvmm.zip")
	rich := &fakeRichRunner{richText: `{"ok":true}`, richOK: true}
	f := &LLMFallback{pyBridge: rich}

	f.toolExecutePython(context.Background(), map[string]any{
		"skill_name": "zip_crack",
		"params":     fmt.Sprintf(`{"path":%q}`, inboxFile),
	}, richChallenge())

	if rich.calls != 1 {
		t.Fatalf("收件箱里的附件路径被拦（附件题会变成不可解）：calls=%d", rich.calls)
	}
}

// 反例二：纯数学参数（ctf_sage 模板）不得被误伤 —— 数字/数组里没有路径。
func TestExecutePythonAllowsMathParams(t *testing.T) {
	rich := &fakeRichRunner{richText: `{"ok":true,"roots":[1]}`, richOK: true}
	f := &LLMFallback{pyBridge: rich}

	got := f.toolExecutePython(context.Background(), map[string]any{
		"skill_name": "ctf_sage_t1_coppersmith",
		"params":     `{"modulus":10001,"poly":[1,2,3],"beta":"1"}`,
	}, richChallenge())

	if rich.calls != 1 {
		t.Fatalf("数学参数被误拦（模板能力会被砍掉）：%q", got)
	}
	if rich.gotExtra == nil || rich.gotExtra["modulus"] == nil {
		t.Fatalf("参数未透传到桥接层：%v", rich.gotExtra)
	}
}
