package runnerl3

// 本地工件清单注入（2026-11-01）。
//
// ## 为什么必须加
//
// `read_attachment` 工具只认 http URL（内部 http.Get 下载），本地工件塞不进
// `ch.AttachmentURLs`；而 `buildUserPrompt` **只在 AttachmentURLs 非空时**才列附件。
// 于是出现一桩"harness 说准备好了、模型却一无所知"的事故：
//
//	2026-11-01 ycb2026 静态题跑批 —— harness 已把 VVMM.exe 复制进工作目录并 chdir 进去，
//	报告里 has_attachment=true；但模型 **一次 python_session 都没调用**（路径审计实测
//	工具调用数 = 0）。不是模型不用工具，是它根本不知道手边有东西可用。
//
// 教训（可复用判据）：**"harness 准备好" ≠ "模型用得上"**。
// 光把自己写进报告的字段当证据，就会把一次空跑读成能力结论。
//
// ## 判据
//
// 只披露 **cwd 之内**的文件名 + 大小（cwd 与路径围栏同源，见 fenceWorkdir），
// 不披露内容、不披露 cwd 之外的任何路径 —— 避免"为可用性顺手把文件系统地图交出去"。
//
// 逃逸阀：`RUNNER_LOCAL_ARTIFACT_HINT=0` 关闭（默认开启）。
import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// maxArtifactEntries 清单条目上限：超了只报数量（宁可少说，不可把 prompt 灌成列表墙）。
	maxArtifactEntries = 40
	// maxArtifactDepth 递归深度上限：附件常见 distfiles/ 一层，再深意义不大且噪音高。
	maxArtifactDepth = 2
)

// localArtifactHint 返回给模型的本地工件说明段；无工件或已关闭时返回空串。
func localArtifactHint() string {
	if !envBool("RUNNER_LOCAL_ARTIFACT_HINT", true) {
		return ""
	}
	wd, err := os.Getwd()
	if err != nil || wd == "" {
		return ""
	}

	entries, total := collectArtifacts(wd)
	if len(entries) == 0 {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "本地工件（无需下载，直接读文件即可）：\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "  - %s (%s)\n", filepath.ToSlash(path.Join(wd, e.rel)), humanBytes(e.size))
	}
	if total > len(entries) {
		fmt.Fprintf(&b, "  - ……另有 %d 项未列出（可用 os.listdir('%s') 自行查看）\n",
			total-len(entries), filepath.ToSlash(wd))
	}
	// 必须写清这条：python_session 的 cwd 是**会话临时目录**（py_session.go 里
	// os.chdir(sys.argv[1]) 是刻意设计，为题目间零状态泄漏），不等于工件目录。
	// 2026-11-01 假端点实测：若提示"用相对路径"而实际 cwd 是空临时目录，
	// 模型 open('VVMM.exe') 必然 FileNotFoundError —— 提示必须给绝对路径。
	fmt.Fprintf(&b, "（注意：python_session 的 cwd 是会话临时目录，不是上面这个目录；"+
		"读工件请用上面的绝对路径，或先 os.chdir('%s')。)\n", filepath.ToSlash(wd))
	return strings.TrimRight(b.String(), "\n")
}

type artifactEntry struct {
	rel  string
	size int64
}

// collectArtifacts 广度受限地遍历 root（≤2 层），跳过隐藏项，返回去重排序后的清单。
func collectArtifacts(root string) ([]artifactEntry, int) {
	var out []artifactEntry
	var walk func(dir, prefix string, depth int)
	walk = func(dir, prefix string, depth int) {
		if depth > maxArtifactDepth || len(out) >= maxArtifactEntries {
			return
		}
		items, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Name() < items[j].Name() })
		for _, it := range items {
			if strings.HasPrefix(it.Name(), ".") {
				continue
			}
			rel := it.Name()
			if prefix != "" {
				rel = path.Join(prefix, it.Name())
			}
			info, err := it.Info()
			if it.IsDir() {
				if depth < maxArtifactDepth {
					walk(path.Join(dir, it.Name()), rel, depth+1)
				} else {
					out = appendDir(out, rel+"/")
				}
				continue
			}
			if err != nil {
				continue
			}
			if len(out) >= maxArtifactEntries {
				return
			}
			out = append(out, artifactEntry{rel: rel, size: info.Size()})
		}
	}
	walk(root, "", 1)

	total := len(out)
	seen := map[string]bool{}
	uniq := make([]artifactEntry, 0, len(out))
	for _, e := range out {
		if seen[e.rel] {
			continue
		}
		seen[e.rel] = true
		uniq = append(uniq, e)
	}
	if len(uniq) > maxArtifactEntries {
		uniq = uniq[:maxArtifactEntries]
	}
	return uniq, total
}

func appendDir(dst []artifactEntry, rel string) []artifactEntry {
	if len(dst) >= maxArtifactEntries {
		return dst
	}
	return append(dst, artifactEntry{rel: rel, size: 0})
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
