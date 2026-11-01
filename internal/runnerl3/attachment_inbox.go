package runnerl3

// 附件收件箱（2026-11-01）。
//
// ## 为什么需要它
//
// `read_attachment` 把下载到的附件落在 `os.TempDir()` **根下**
// （`/tmp/secautomind_att_<name>`），而 2026-11-01 加的 python_session 围栏只放行
// 「会话目录 + 题目工作目录 + 只读系统路径」。两者一撞，模型拿到的附件路径
// 会被围栏自己挡回去：
//
//	read_attachment → 路径: /tmp/secautomind_att_vvmm.zip
//	python_session  → 拒绝执行：代码引用了本题工作区之外的路径 [/tmp/secautomind_att_vvmm.zip]
//
// 后果不是"少个功能"，而是**把附件题直接做成不可解**：YCB 两道题正是靠附件
// （VVMM.exe / 内存镜像）才有唯一解法，围栏一挡，跑批会得到"模型不会用工具"的
// 假结论 —— 而真因是我们自己的两段代码口径不一致。
//
// 但也不能反过来把整个 `/tmp` 加进白名单：2026-11-01 真机取证显示同一台机器的
// `/tmp` 里有并行会话的其他题目残留、别的基准的 `app.log`、甚至**别人的私钥**
// （`/tmp/bench_keys_*/agent_*_private.pem`）—— 放开 `/tmp` 等于把刚堵上的
// 跨会话越权与原路重开。
//
// ## 做法
//
// 收件箱 = `os.TempDir()/secautomind_att_<pid>_<cwd哈希前8位>`：
//   - **按进程 + 按工作目录分桶** ⇒ 别的进程/别的题的附件不在本桶内，读不到；
//   - 只有 `read_attachment` 写它，里面的文件全部来自**本次运行主动下载**的 URL，
//     不存在"别人的答案文件"这类东西；
//   - 围栏把**这一个目录**（而不是 `/tmp`）加进白名单。
//
// 换言之：围栏放行的范围恰好等于「本进程本次题目下载的附件」，不多一个字节。
//
// ## 清理
//
// 目录由 OS 临时目录清理机制兜底（`/tmp` 本就不是持久区）；
// `cmd/llmbench` 的每题工作目录已按题清理，附件桶按进程分桶不会跨题串味。
import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// attachmentInboxDir 返回本进程当前工作目录对应的附件收件箱目录（已创建）。
//
// 目录名里带 cwd 哈希，是为了让"一进程跑多题"（cmd/llmbench 顺序跑批）时
// 每题的附件互不可见 —— 否则上一题下载的 `flag.txt` 会留在桶里被下一题读到，
// 那又是一种"答案从别的题漏进来"的污染形态（围栏挡不住，因为它在白名单内）。
func attachmentInboxDir() string {
	name := fmt.Sprintf("secautomind_att_%d", os.Getpid())
	if wd, err := os.Getwd(); err == nil && wd != "" {
		sum := sha256.Sum256([]byte(wd))
		name += "_" + hex.EncodeToString(sum[:4])
	}
	dir := filepath.Join(os.TempDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		// 建不出来就退回临时目录根：宁可让围栏挡下（模型会看到明确拒因），
		// 也不要让下载直接失败成"附件不可用"。
		return os.TempDir()
	}
	return dir
}

// attachmentInboxFenceRoot 返回收件箱在**围栏坐标系**里的形态。
//
// 围栏比对的是代码文本里的 POSIX 绝对路径（见 path_fence.go：刻意不用 filepath，
// 因为 Windows 上 filepath.Clean 会把 /tmp/x 变成 \tmp\x，前缀比对全落空）。
// 所以这里统一转成以 `/` 分隔的形态；Linux 上是恒等变换。
func attachmentInboxFenceRoot() string {
	return filepath.ToSlash(attachmentInboxDir())
}
