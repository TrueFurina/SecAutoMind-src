package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// 本文件是「西湖论剑已彻底并入」在运行层的守门测试。
//
// 背景：2026-10-25 收口时发现 cmd/runner 整个包**没有任何测试**，
// 而 pyskill_bridge.go 早就准备好了 osGetwd/osStat 两个可注入包装函数——
// 说明当初就想测，只是一直没写。补上。

// TestCandidateSkillDirsAreRepoLocal 是「吞并是否彻底」的机器可验证判据。
//
// 判据：候选 skills 目录必须全部由 cwd 派生（仓库内），
// 不得出现任何仓库外的绝对路径。
//
// 一旦有人再把 `E:\Program\西湖论剑\ctf_agent\skills` 这类路径写回去，
// 本用例立刻红——「吞并」就不会退化成只在文档里成立。
func TestCandidateSkillDirsAreRepoLocal(t *testing.T) {
	cwd, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("取 cwd 失败：%v", err)
	}

	dirs := candidateSkillDirs()
	if len(dirs) == 0 {
		t.Fatal("候选目录为空——findSkillsDir 将永远返回空串，Layer 2 静默失效")
	}

	// Windows 路径大小写不敏感，统一小写比较
	lowCwd := strings.ToLower(cwd)
	for _, d := range dirs {
		if !strings.HasPrefix(strings.ToLower(d), lowCwd) {
			t.Errorf("候选目录不在仓库内：%q（cwd=%q）\n"+
				"硬编码外部路径会让「吞并」停留在名义上：源仓被删除或改名后行为不可预期", d, cwd)
		}
	}
}

// TestCandidateSkillDirsContainArchive 归档副本必须在候选里。
//
// 源仓那条路径已按「吞并收口」移除，归档副本成了 skills 的唯一权威来源；
// 它若从候选里消失，skills 解析会静默失效（返回空串，不报错）。
func TestCandidateSkillDirsContainArchive(t *testing.T) {
	for _, d := range candidateSkillDirs() {
		if strings.Contains(d, "CTF-Agent_融合") {
			return
		}
	}
	t.Fatal("候选目录里没有 CTF-Agent_融合 归档副本——skills 将无法解析")
}

// TestFindSkillsDirResolvesToArchive 在仓库根执行时，应命中归档副本而非返回空串。
//
// 这条验证的是「候选顺序真的能走通」——只测 candidateSkillDirs 的字符串不够，
// 必须让 findSkillsDir 在真实文件系统上跑一次。
func TestFindSkillsDirResolvesToArchive(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("定位仓库根失败：%v", err)
	}

	t.Chdir(root) // Go 1.24+

	got := findSkillsDir()
	if got == "" {
		t.Fatal("在仓库根仍未解析到 skills 目录——归档副本可能已被移动或删除")
	}
	if !strings.Contains(got, "CTF-Agent_融合") {
		t.Fatalf("期望命中归档副本，实际命中 %q", got)
	}
}

// TestFindSkillsDirFailSafe 候选全不存在时必须返回空串，而不是 panic 或返回垃圾路径。
//
// runner 拿到空串会跳过 Layer 2（确定性技能层），仍能靠 LLM 跑——
// 这是设计好的降级路径，不能因为「找不到目录」就崩掉整个 runner。
func TestFindSkillsDirFailSafe(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp) // 空目录：三个候选都不存在

	if got := findSkillsDir(); got != "" {
		t.Fatalf("候选全不存在时期望空串，实际返回 %q", got)
	}
}

// TestExtractSkillText 锁 extractSkillText 的 regex 不变量。
//
// L2 的 params 靠从 Challenge.Description 里 regex 提取密文才能正确构造。
// 一旦有人改了 regex 格式（比如把 "密文:" 改成 "密文：" 全角冒号），
// L2 会静默降级（skill 收不到 text → 返回 "需要 text 参数"），整条链不报错但解题率归零。
//
// 本测试覆盖 CTF 题描述的常见格式。改 regex 必须同步改测试并说明理由。
func TestExtractSkillText(t *testing.T) {
	cases := []struct {
		name string
		desc string
		want string
	}{
		{"中文冒号", "密文: XPCX{xxkx_1234}，key SECRET", "XPCX{xxkx_1234}"},
		{"中文冒号带等号", "密文= XPCX{xxkx_1234}", "XPCX{xxkx_1234}"},
		{"英文冒号", "Ciphertext: ABC123DEF456", "ABC123DEF456"},
		{"ciphertext 小写", "ciphertext: dGVzdA==", "dGVzdA=="},
		{"text= 等号", "text=FLAG{test}", "FLAG{test}"},
		{"引号包裹", "密文: `XPCX{xxkx_1234}`", "XPCX{xxkx_1234}"},
		{"完全不含密文关键词", "这是一道 Vigenère 密码题，你需要自己分析", ""},
		{"密文是 base64", "encoded: dGVzdA==dGVzdA==", "dGVzdA==dGVzdA=="},
	}
	for _, c := range cases {
		got := extractSkillText(c.desc)
		if got != c.want {
			t.Errorf("%s:\n  desc: %q\n  got:  %q\n  want: %q", c.name, c.desc, got, c.want)
		}
	}
}

// TestExtractSkillKey 锁 extractSkillKey 的 regex 不变量。
//
// Vigenère/Playfair 等 skill 需要 key 参数。Runner L2 从 description 自动提取。
// 改 regex 必须同步改测试。
func TestExtractSkillKey(t *testing.T) {
	cases := []struct {
		name string
		desc string
		want string
	}{
		{"中文密文+key", "密文: XPCX{xxkx_1234}，key SECRET", "SECRET"},
		{"英文 key: ", "Key: MYKEY123 是这道题的密钥", "MYKEY123"},
		{"等号分隔", "secret=FLAGKEY", "FLAGKEY"},
		{"引号包裹", "key: `SECRET_KEEP`", "SECRET_KEEP"},
		{"完全不含 key 关键词", "这道题没有密钥提示", ""},
		{"密钥是单词", "密钥: PASSWORD", "PASSWORD"},
	}
	for _, c := range cases {
		got := extractSkillKey(c.desc)
		if got != c.want {
			t.Errorf("%s:\n  desc: %q\n  got:  %q\n  want: %q", c.name, c.desc, got, c.want)
		}
	}
}
