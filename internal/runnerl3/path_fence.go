package runnerl3

// python_session 的工作目录围栏（2026-11-01）。
//
// ## 为什么必须加这个
//
// 2026-11-01 服务器真机取证（`scripts/experiments/llmbench_path_audit.py`）实锤：
// 解 `ycb12085_vvmm` 时模型用 `python_session` 做了 23 次工具调用，
// **零次落在自己的题目工作目录**，实际读到：
//   - 并行会话另一道题的 `/tmp/current_time_travel/*`
//   - 别的基准残留 `/tmp/deser_range_*/app.log`
//   - **别人的私钥** `/tmp/bench_keys_*/agent_*_private.pem`
//   - **`/home/user` 主目录**
//
// 这不是"不够优雅"，是两条事故链：
//   1. **KPI 污染**：candidate flag 可能来自别人会话的残留文件，判分只认 sha256
//      ⇒ 会被判成**真 HIT**，直接污染「LLM 真实解出数」（性质 = 伪造分数）；
//   2. **横向越权**：模型能读别的会话的私钥和主目录 —— 比赛机上这就是事故。
//
// ## 为什么做在 Exec 而不是别处
//
// `pySessionMgr.Exec` 是 `python_session` 每一次执行的**唯一**入口，
// 在此拦截不需要改 Python 引导脚本、也不依赖 OS 级 sandbox（服务器无 docker，
// 见 cmd/llmbench 文件头）。属于"拦得住的最小切面"。
//
// ## 判据（宁可报错，不可静默放行）
//
// 从**待执行代码文本**里抽绝对路径，逐个比对白名单前缀：
//   - 允许：会话自己的临时目录（`os.MkdirTemp("secautomind_sess_")` 那个）
//   - 允许：题目工作目录 = 创建会话时的进程 cwd（harness 会 chdir 进去）
//   - 允许：只读系统路径（/usr /lib /lib64 /bin /sbin /etc /proc /sys /dev /opt）
//   - 其余一律拒绝，重点包括**其他 /tmp/* 子目录**与 /home、/root、/var 数据区
// 相对路径不受限（cwd 已在允许区内）。
//
// 被拒时**明确告诉模型哪些路径越界、哪些能用**，而不是静默失败 ——
// 让它可以改用会话临时目录继续干活。
//
// 逃逸阀：`RUNNER_PY_FENCE=0` 可整体关闭（默认开启）。留它是为了不把
// 未来某个合法的跨目录用法一棍子打死，但**默认必须开着**。
import (
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

// absPathRe 抽取代码里的绝对路径（至少两级）。
//
// 三处刻意的形态约束，都是被自测/真机打出来的：
//  1. 左侧必须有边界符（引号/空白/逗号等），否则 `"./data/x.bin"` 里的 `/data/x.bin`
//     会被误当成绝对路径 —— 相对路径误报会把正常解题卡死；
//  2. 只认 `/` 开头的 POSIX 形态：解题只在 Linux 服务器上跑（AGENTS.md 第零条），
//     用 filepath 处理会在 Windows 上把 /usr/bin Clean 成 \usr\bin ⇒ 白名单全失效；
//  3. 基类必须是「非空白非引号非括号」而不是 `[A-Za-z0-9_.-]`：2026-11-01 自测
//     打出的真空洞 —— 归档目录叫 `西湖论剑归档_20260821`，旧类遇中文直接**整条
//     路径都抽不出来**，围栏等于对这批文件全盲（正是含 flag 明文的那批）。
//     同理排除 `{}`：`f"/home/{x}/y"` 这类格式串不是真实路径，抽出来只会误报。
var absPathRe = regexp.MustCompile(`(?:^|[\s"''(,=\[])(/[^\s"''()\[\]<>,;|{}]+(?:/[^\s"''()\[\]<>,;|{}]+)+)`)

// systemPrefixes 进程正常运行必然要碰的只读系统路径。
var systemPrefixes = []string{
	"/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/etc/",
	"/proc/", "/sys/", "/dev/", "/opt/",
}

// pathFence 判定一段代码是否越出了允许的工作区。
type pathFence struct {
	allowed []string // 已 Clean 的绝对目录前缀
	enabled bool
}

// denyFragments 默认拒绝的敏感路径片段（2026-11-01 实锤后加）。
//
// 起因：围栏按"进程 cwd"建白名单，而 harness 对**纯文本题**不做 chdir ⇒
// cwd 落在仓库根 ⇒ 整个仓库被当白名单。假端点实测到模型能读
// `data/answers/ycb2026_truth.json`（明文真值）——
// 只要读了它再原样提交，sha256 必然匹配，就会在账本上记成"LLM 解出"。
// 这是**活的伪造分数通道**，不是理论风险。
//
// 所以即便路径在 allowed 之内，命中下列片段也一律挡：
// 答案目录 / 版本库 / 私钥文件。宁可误挡（模型改用别的方式），不可放过。
var denyFragments = []string{
	"/data/answers/", "/answers/", "/.git/", "/.ssh/",
	"/ycb2026_truth", "/benchmark_truth",
	// 2026-11-01：归档 writeup（71 篇里 22 篇含 flag 明文）。仓库根已由
	// fenceWorkdir 按目录身份整体挡掉，这条是纵深防御 —— 万一有别的入口
	// 把仓库子目录当工作区，仍读不到这批已知答案。
	"/docs/evidence/",
	// 2026-11-01 09:04 真机：模型用 `print(os.environ)` 收走了 API key 明文。
	// 环境变量已经由 internal/procenv 白名单化，但 `/proc/<pid>/environ` 是
	// **同一个出口的文件形态** —— 子进程读父进程的 environ 照样拿到全量。
	// 这条片段同时挡住 /proc/self/environ 与 /proc/1/environ。
	"/environ",
}
var denySuffixes = []string{".pem", ".key", "id_rsa", "id_ed25519"}

// newPathFence 建立围栏。roots 是允许读写的目录（会话目录 + 题目工作目录）。
func newPathFence(roots ...string) *pathFence {
	f := &pathFence{enabled: os.Getenv("RUNNER_PY_FENCE") != "0"}
	seen := map[string]bool{}
	for _, r := range roots {
		if r == "" {
			continue
		}
		// 用 path.Clean 而非 filepath.Clean：解题只在 Linux 服务器跑，
		// filepath 在 Windows 上会把 /tmp/x 变成 \tmp\x ⇒ 前缀比对全部落空。
		c := path.Clean(r)
		if seen[c] {
			continue
		}
		seen[c] = true
		f.allowed = append(f.allowed, c)
	}
	sort.Strings(f.allowed)
	return f
}

func (f *pathFence) isAllowed(p string) bool {
	p = path.Clean(p)
	if isDenied(p) {
		return false
	}
	for _, root := range f.allowed {
		if p == root || strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	for _, pre := range systemPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// isDenied 判断路径是否命中敏感片段（答案/密钥/版本库）。命中即拒，不看 allowed。
func isDenied(p string) bool {
	lp := strings.ToLower(p)
	for _, frag := range denyFragments {
		if strings.Contains(lp, frag) {
			return true
		}
	}
	base := path.Base(lp)
	for _, suf := range denySuffixes {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	return false
}

// violations 返回代码里所有越界的绝对路径（已去重、排序，便于写进错误信息）。
func (f *pathFence) violations(code string) []string {
	if f == nil || !f.enabled {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range absPathRe.FindAllStringSubmatch(code, -1) {
		if len(m) < 2 {
			continue
		}
		p := path.Clean(strings.TrimRight(m[1], ".,;:!?)]}'\""))
		if seen[p] || f.isAllowed(p) {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// describeAllowed 给模型的回执里列清楚"能写哪儿"，否则它只能瞎试。
func (f *pathFence) describeAllowed() string {
	parts := append([]string{}, f.allowed...)
	parts = append(parts, "只读系统路径 (/usr /lib /bin /etc /proc ...)")
	return strings.Join(parts, " | ")
}

// fenceWorkdir 返回题目工作目录 = 进程当前目录。
//
// 为什么用进程 cwd：harness（`cmd/llmbench` 的 prepareWorkdir）会在 Solve 之前
// `os.Chdir` 进每题的工作目录，会话又在 Solve 期间创建 ⇒ cwd 就是本题工作区。
// 取不到时返回空串，**由 newPathFence 忽略** —— 不猜默认根目录，收缩了顶多是多挡，
// 不会放开。
//
// 2026-11-01 补第二条：**代码仓库自身永远不是题目工作区**。
// 生产 runner 由 runbook 用 `cd ~/SecAutoMind_verify && ./runner` 启动 ⇒ 进程 cwd
// = 仓库根 ⇒ 整个仓库进白名单。denyFragments 只能挡已知文件名模式，挡不住
// `docs/evidence/西湖论剑归档_20260821/solutions/` 里那批 writeup：
// 71 个文件里 22 个含 flag 形态明文（本轮实点）。模型读到即"命中"，
// 性质与被 deny 表挡掉的 data/answers 完全相同 —— 都是伪造分数。
// 所以按**目录身份**判定并 fail-closed：宁可让模型只用会话目录，
// 也不把仓库当工作区。需要放行时用 `RUNNER_PY_FENCE_ALLOW_REPO=1` 显式降级留痕。
func fenceWorkdir() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	if isProjectSourceTree(wd) && !envBool("RUNNER_PY_FENCE_ALLOW_REPO", false) {
		return ""
	}
	return wd
}

// projectMarkerFiles 项目源码树的身份标记。命中任意一个即认定"这是代码仓库"。
//
// 为什么不用"是否等于某个写死路径"：仓库在服务器上叫 SecAutoMind_verify、
// 在本机叫 SecAutoMind，克隆名随时会变；而 go.mod / AGENTS.md 是内容身份，
// 换目录名照样成立。
var projectMarkerFiles = []string{"go.mod", "AGENTS.md", "cmd/runner/main.go"}

// isProjectSourceTree 判断 dir 是否是本项目的代码树（而非某道题的工作区）。
//
// 判据是"命中 ≥2 个身份标记"而不是"命中任意一个"：逆向/源码题的附件里
// 完全可能带一个 `go.mod`（那就是题面输入），若按单标记判定，这道题的
// 工作区会被自身围栏锁死 —— 模型连自己的附件都读不到，比越权更糟。
// 同时命中 go.mod + AGENTS.md（或含 cmd/runner/main.go）的目录只可能是本仓库。
func isProjectSourceTree(dir string) bool {
	if dir == "" {
		return false
	}
	hits := 0
	for _, m := range projectMarkerFiles {
		if _, err := os.Stat(path.Join(dir, m)); err == nil {
			hits++
		}
	}
	return hits >= 2
}
