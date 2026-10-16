package ctfplatform

// answer_key_git_gate_test.go —— 交付红线的 git 层门禁。
//
// 由来（2026-10-15 真实破防）：PR #22 处置"答案文件不入 PUBLIC 仓"时，
// 在 `attachments/.gitignore` 里列了答案文件，但 **`10733/task.py` 早已在更早的
// 提交里被 `git add`过** —— .gitignore 只对**未跟踪**文件生效，对已跟踪文件无效，
// 于是该文件一直留在 PUBLIC 远端 main 上，直到本轮才发现：
//
//	git cat-file -p ghssh/main:data/.../10733/task.py | grep -cE '^(hint|c|n)= [0-9]{20,}'
//	→ 3   （hint / c / n 三行实例真值全在远端）
//
// 代价：项目自己的交付红线（PUBLIC 仓禁答案明文入库）被静默破了两个多月，
// 而 `.gitignore` 的存在让人误以为问题已解决。**这是"看起来做过 vs 真的有效"的
// 典型样本**，与 AGENTS.md 第四条（门禁必须真能失败）同源。
//
// 本门禁把"gitignore 列出的就是不该入库的"这条断言变成 CI 可复跑的检查，
// 且**同时校验两个层面**：
//  1. .gitignore 命中：该路径确实被规则匹配（规则本身有效）；
//  2. 未被跟踪：`git ls-files` 不含该路径（历史遗留的跟踪已清理）。
// 只查第1 层会漏掉本例（.gitignore 一直是"对"的）；只查第 2 层则对新文件无约束。
//
// ⚠️ 2026-10-16 留痕（本例的后续）：`10733/task.py` 经复核**撤销排除**——它不含 flag
// （`flag = b'******'` 遮蔽态），内容只是加密脚本 + hint/c/n 实例参数，属**题目输入**，
// 与同批已入库的 ezrsa 等附件同类。本文件注释所引的旧事件仍然是真实的（**已跟踪文件不受
// .gitignore 影响**这条教训一字未改），但"该文件是答案材料"这一当时判断已被证伪，
// 故它现在既不在此清单、也不在 `.gitignore` 里。钉死方向由
// data_incomplete_claim_test.go::TestInstanceTruthNailHolds 与
// scripts/check_cross_bench_manifest.py::FORBIDDEN_EXCLUDED 反向把守（不得再被排除）。
// 判定"是否答案材料"的权威口径仍是本文件的 `flagPlaintextRe`（flag 明文形态）——
// **裸参数/数字是题目输入，不算答案**。

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// flagPlaintextRe 只认「品牌前缀 + 花括号内容」的真 flag 形态。
// 刻意不含 `flag{...}` 通用形（那可能只是题目格式说明，例如题面写
// "flag 格式为DASCTF{xxx}"），也不认裸数字/参数形态（那些是题目输入）。
var flagPlaintextRe = regexp.MustCompile(`(?i)\b((?:dasctf|picoctf|buuctf|bctf|n1ctf|ezctf|suctf|ciscn|cnss|ghctf|wolvctf|doubao|buu|hn|crypto|reverse|web|misc)\{[^}\n]{6,80}\})`)

// gitignoreLines 读 attachments/.gitignore 的非注释、非空条目。
func gitignoreLines(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "data", "questions_real_bench", "attachments", ".gitignore"))
	if err != nil {
		t.Skipf("attachments/.gitignore 缺失: %v", err)
	}
	var out []string
	for _, ln := range strings.Split(string(raw), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		out = append(out, ln)
	}
	return out
}

func gitLines(t *testing.T, args ...string) []string {
	t.Helper()
	cmd := exec.Command("git", args...)
	// ⚠️ 必须显式指到仓库根：exec 的默认工作目录是**包目录**（internal/ctfplatform），
	//    而所有传给 git 的路径参数都是仓库根相对的。初版漏了 Dir，
	//    导致 `git ls-files` 返回空 → "已跟踪附件 0 个"被误判成"git 不可用"而 SKIP，
	//    **又是一次零覆盖静默通过**（与 data_incomplete_claim_test 的 t.Skipf 同款）。
	cmd.Dir = ".." + string(filepath.Separator) + ".."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v 执行失败（这是环境问题，不是通过依据）: %v", args, err)
	}
	var res []string
	for _, ln := range strings.Split(string(out), "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			res = append(res, ln)
		}
	}
	return res
}

// TestAnswerKeyFilesNotTracked 断言：.gitignore 里列出的答案文件，
// 既被规则命中，**也未被 git 跟踪**。
//
// 报红含义（两种，都要处理）：
//   · 未被规则命中 → .gitignore 规则写错了（新文件漏网）；
//   · 仍被跟踪     → 历史遗留跟踪，须 `git rm --cached <路径>`（本地文件保留）。
// 修复动作**绝不能是** `git rm`（会删本地文件，破坏本地跑分），
// 也不许改.gitignore 把它摘出来（那是破红线）。
func TestAnswerKeyFilesNotTracked(t *testing.T) {
	pats := gitignoreLines(t)
	if len(pats) == 0 {
		t.Skip(".gitignore 无有效条目")
	}
	tracked := gitLines(t, "ls-files", "data/questions_real_bench/attachments/")

	trackedSet := make(map[string]bool, len(tracked))
	for _, p := range tracked {
		trackedSet[p] = true
	}

	base := "data/questions_real_bench/attachments/"
	var ruleMiss, stillTracked []string
	for _, pat := range pats {
		full := base + pat
		// 层面 1：规则是否真的命中磁盘上的文件
		// ⚠️ 两条易错点，都已在实测中踩过：
		//  1. `git check-ignore` 的语义是 **退出码 0 = 被规则命中**，1 = 未命中；
		//     初版把语义写反，导致"全部命中"被报成"未命中"。
		//  2. 传给它的路径必须是**相对仓库根**的，而 exec 的默认工作目录是**包目录**
		//     （internal/ctfplatform）。不显式设 Dir 就会全部判成"未命中"。
		cmd := exec.Command("git", "check-ignore", "-q", full)
		cmd.Dir = ".." + string(filepath.Separator) + ".."
		if err := cmd.Run(); err != nil {
			ruleMiss = append(ruleMiss, pat+"（规则未命中）")
		}
		// 层面 2：是否仍被跟踪（本例的核心漏洞点）
		if trackedSet[full] {
			stillTracked = append(stillTracked, pat)
		}
	}

	for _, p := range ruleMiss {
		t.Errorf("🔴 .gitignore 规则未命中：%s —— 规则写错了，该文件仍可能被误提交", p)
	}
	if len(stillTracked) > 0 {
		t.Errorf("🔴 交付红线破防：以下答案文件仍在 git 跟踪中（.gitignore 对已跟踪文件无效）：%v\n"+
			"  修复：git rm --cached <路径>（**保留本地文件**，本地跑分需要它）\n"+
			"  🔴 绝不能用 git rm（会删本地文件），也不许把它从 .gitignore 摘出来（那是破红线）\n"+
			"  提示：历史上曾因『.gitignore 已列』误判为已处理，实际文件早被 git add 过（PR #22）",
			stillTracked)
	}
	if len(ruleMiss) > 0 || len(stillTracked) > 0 {
		return // 已报红，不再输出"全部通过"的日志（避免日志与结论自相矛盾）
	}
	t.Logf("答案文件红线检查：.gitignore %d 条，全部规则命中且未被跟踪 ✅（本地文件保留供含答案口径跑分）",
		len(pats))
}

// TestTrackedAnswerKeyHasNoPlaintextTruth 兜底扫描：已跟踪的附件里若出现
// **flag 明文**（`DASCTF{...}` / `picoCTF{...}` 之类的真值形态），说明答案材料漏进
// 了 PUBLIC 仓——**跨过 .gitignore 机制兜底**。
//
// 与上一条互补：上一条按"已知答案文件清单"查，本条按"内容形态"查，
// 能抓到清单没登记、但实际含真值的新文件（本例即属此类：10733/task.py 当时未在 .gitignore）。
//
// ⚠️ 口径教训（实测踩过，勿放宽）：初版用「`x=` + 40 位十进制」或「≥80 位连续十进制」
// 判定，结果把 4 个**合法入库的赛题附件**误判为泄露——它们的 output 里全是
// 题目参数（617 位 challenge 编号、2048 位 LFSR 初始状态），**并不含 flag 明文**
// （实测 `含flag 明文 = False`）。这四个附件正是已命中题目的输入，本就该入库。
//
// 因此口径收窄为**只认 flag 明文**（品牌前缀 + 花括号内容），因为那才是真正的答案。
// 反过来，`data_incomplete_claim_test.go` 里的宽松口径是对的——那边判的是
// "归因是否为数据不完整"（宁可误报），这边的判的是"是否泄露"（必须准），**两侧口径
// 故意不同，不可互相复用**。
func TestTrackedAnswerKeyHasNoPlaintextTruth(t *testing.T) {
	tracked := gitLines(t, "ls-files", "data/questions_real_bench/attachments/")
	if len(tracked) == 0 {
		t.Fatal("🔴 已跟踪附件为 0 —— 要么真的一个都没跟踪（不该发生），" +
			"要么 git 调用路径不对。**绝不能把'查不到'当成'没有泄露'**——" +
			"这正是本门禁要防的那类假绿。")
	}
	// 直接扫工作树文件内容（本门禁关心"这些被跟踪的文件里有没有答案明文"）。
	leaks := []string{}
	for _, rel := range tracked {
		raw, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		if looksBinary(raw) {
			continue
		}
		if flagPlaintextRe.Match(raw) {
			leaks = append(leaks, rel+"（含flag 明文）")
		}
	}
	if len(leaks) > 0 {
		t.Errorf("🔴 已跟踪附件含实例真值赋值（疑似答案材料入 PUBLIC 仓）：%v\n"+
			"  这些文件必须：1) git rm --cached <路径> 停止跟踪（保留本地）"+
			"  2) 登记进 attachments/.gitignore  3) 在 cross_bench.json 标 answer_key_shape+git_excluded",
			leaks)
	}
	t.Logf("已跟踪附件 %d 个，形态扫描未发现实例真值赋值", len(tracked))
}