package runnerl3

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ── P1-2 交互会话状态（2026-10-26）──────────────────────────────────────────
//
// 计划依据（求解能力深化计划 L152-154）：exec/execute 从一次性命令升级为**有状态会话**
// （cwd/变量/连接跨步保持）。EnIGMA 实证 ~3×（11%→36%）；STRIATUM-CTF 用它治
// 独白与上下文漂移（失败模式 ⑨⑪）。
//
// 形态：一个长期存活的 Python 子进程 + JSON-lines 协议。每次调用把代码送进同一个
// globals 里 exec —— 变量、import、cwd、打开的文件句柄**跨步保持**，这才是"会话"。
// 对照：既有 execute_python 是一次性 skill 子进程（每次都从零开始），多步推理里
// 模型只能靠"把中间结果写回文本再重述"来维持状态，是独白式漂移的温床。
//
// 安全与硬限（与 execute_python 同口径，另加会话专属两条）：
//   1. 每题一个独立会话 + 独立临时 cwd（题目之间零状态泄漏）；
//   2. 单条命令超时 → 杀掉会话并**如实告知状态已丢失**（不假装还在），下次调用惰性重启；
//   3. stdout/stderr 截断（防输出炸弹）；
//   4. Solve 返回即 Close（defer），不留僵尸进程。

// pyBootstrap 是会话子进程的主循环（JSON-lines：一行请求 → 一行响应）。
// -u 保证不缓冲；os.chdir 到会话目录使 cwd 跨步保持。
const pyBootstrap = `
import sys, os, io, json, contextlib
if len(sys.argv) > 1:
    os.chdir(sys.argv[1])
G = {"__name__": "__main__"}
print(json.dumps({"ready": True}), flush=True)
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except Exception:
        sys.stdout.write(json.dumps({"id": -1, "ok": False, "err": "bad request"}) + "\n"); sys.stdout.flush()
        continue
    rid = req.get("id")
    code = req.get("code", "") or ""
    if req.get("reset"):
        G = {"__name__": "__main__"}
    out, err = io.StringIO(), io.StringIO()
    ok = True
    result = ""
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            exec(compile(code, "<session>", "exec"), G)
        r = G.get("_", None)
        if r is not None:
            try:
                result = repr(r)[:2000]
            except Exception:
                result = ""
    except BaseException as e:
        ok = False
        err.write("%s: %s" % (type(e).__name__, e))
    sys.stdout.write(json.dumps({
        "id": rid, "ok": ok, "cwd": os.getcwd(),
        "out": out.getvalue()[-8000:], "err": err.getvalue()[-2000:], "result": result,
    }) + "\n")
    sys.stdout.flush()
`

// pySession 是一个长期存活的 Python 会话进程。
type pySession struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	reader *bufio.Reader
	dir    string
	logger *zap.Logger

	mu  sync.Mutex
	seq int
}

// pySessionMgr 惰性启动 + 失败重启 + 统一销毁（每题一个）。
type pySessionMgr struct {
	mu       sync.Mutex
	sess     *pySession
	pyPath   string
	logger   *zap.Logger
	closed   bool
	restarts int
}

// pythonCandidates 与 cmd/runner/pyskill_bridge.go 保持同一套解析顺序：
// python3（Linux/macOS）→ python → Windows venv 默认路径。
var pythonCandidates = []string{"python3", "python", `C:\Users\Lenovo\.workbuddy\binaries\python\envs\default\Scripts\python.exe`}

// ResolvePython 返回可用的 Python 解释器路径；找不到返回 ""。
func ResolvePython() string {
	for _, c := range pythonCandidates {
		if p, err := exec.LookPath(c); err == nil && p != "" {
			return p
		}
	}
	return ""
}

func newPySessionMgr(logger *zap.Logger) *pySessionMgr {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &pySessionMgr{pyPath: ResolvePython(), logger: logger}
}

// startSession 启动一个新会话（调用方需持有 m.mu）。
func (m *pySessionMgr) startSession() (*pySession, error) {
	if m.pyPath == "" {
		return nil, fmt.Errorf("未找到可用 Python 解释器（python3/python/venv 均不在 PATH）")
	}
	dir, err := os.MkdirTemp("", "secautomind_sess_")
	if err != nil {
		return nil, fmt.Errorf("创建会话目录失败: %w", err)
	}
	cmd := exec.Command(m.pyPath, "-u", "-c", pyBootstrap, dir)
	cmd.Dir = dir
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("stdin 管道失败: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("stdout 管道失败: %w", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("启动会话进程失败: %w", err)
	}
	s := &pySession{cmd: cmd, stdin: stdin, reader: bufio.NewReader(stdout), dir: dir, logger: m.logger}
	// 等 ready 握手（防止把启动错误当成命令结果）
	line, err := s.reader.ReadString('\n')
	if err != nil {
		_ = s.kill()
		return nil, fmt.Errorf("会话就绪握手失败: %w", err)
	}
	var hs struct {
		Ready bool `json:"ready"`
	}
	if err := json.Unmarshal([]byte(line), &hs); err != nil || !hs.Ready {
		_ = s.kill()
		return nil, fmt.Errorf("会话就绪握手续列异常: %q", strings.TrimSpace(line))
	}
	return s, nil
}

// Exec 在会话里执行一段代码。reset=true 时先清空用户变量（cwd 仍保留）。
// 会话未启动时惰性启动；单条命令超时则杀会话并如实报错（下次调用会重启）。
func (m *pySessionMgr) Exec(ctx context.Context, code string, reset bool) (string, error) {
	if strings.TrimSpace(code) == "" {
		return "", fmt.Errorf("code 为空")
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return "", fmt.Errorf("会话已关闭")
	}
	if m.sess == nil {
		s, err := m.startSession()
		if err != nil {
			m.mu.Unlock()
			return "", err
		}
		m.sess = s
	}
	sess := m.sess
	m.mu.Unlock()

	out, err := sess.exec(ctx, code, reset)
	if err != nil {
		// 超时/断管：会话已不可信 → 销毁，下次惰性重启（真话：状态没了）
		m.mu.Lock()
		if m.sess == sess {
			_ = sess.kill()
			m.sess = nil
			m.restarts++
		}
		m.mu.Unlock()
		return "", err
	}
	return out, nil
}

// Close 销毁会话并清理临时目录。Solve 用 defer 调用，避免僵尸进程与临时目录堆积。
func (m *pySessionMgr) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	if m.sess != nil {
		_ = m.sess.kill()
		m.sess = nil
	}
}

// exec 发送一条命令并等待一行响应（单条命令超时由调用方 ctx 或默认 60s 控制）。
func (s *pySession) exec(ctx context.Context, code string, reset bool) (string, error) {
	s.mu.Lock()
	s.seq++
	id := s.seq
	s.mu.Unlock()

	req, err := json.Marshal(map[string]any{"id": id, "code": code, "reset": reset})
	if err != nil {
		return "", fmt.Errorf("序列化请求失败: %w", err)
	}
	if _, err := io.WriteString(s.stdin, string(req)+"\n"); err != nil {
		return "", fmt.Errorf("写入会话失败: %w", err)
	}

	type respT struct {
		line string
		err  error
	}
	ch := make(chan respT, 1)
	go func() {
		line, err := s.reader.ReadString('\n')
		ch <- respT{line: line, err: err}
	}()

	timeout := 60 * time.Second
	if d, ok := ctx.Deadline(); ok {
		if remain := time.Until(d); remain > 0 && remain < timeout {
			timeout = remain
		}
	}
	select {
	case r := <-ch:
		if r.err != nil {
			return "", fmt.Errorf("读取会话响应失败: %w", r.err)
		}
		return s.render(r.line)
	case <-time.After(timeout):
		return "", fmt.Errorf("会话命令超时（%v），会话已销毁、状态丢失", timeout)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// render 把响应 JSON 渲染成给 LLM 看的文本（与既有工具的 bracket 约定对齐）。
func (s *pySession) render(line string) (string, error) {
	var r struct {
		ID     int    `json:"id"`
		OK     bool   `json:"ok"`
		CWD    string `json:"cwd"`
		Out    string `json:"out"`
		Err    string `json:"err"`
		Result string `json:"result"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &r); err != nil {
		return "", fmt.Errorf("解析会话响应失败: %w（原文 %q）", err, truncate(line, 200))
	}
	var b strings.Builder
	if r.OK {
		b.WriteString("[python_session 成功]")
	} else {
		b.WriteString("[python_session 报错]")
	}
	if r.CWD != "" {
		b.WriteString(" cwd=" + filepath.Base(r.CWD))
	}
	if strings.TrimSpace(r.Out) != "" {
		b.WriteString("\n--- stdout ---\n" + truncate(r.Out, 4000))
	}
	if strings.TrimSpace(r.Result) != "" {
		b.WriteString("\n--- _ ---\n" + truncate(r.Result, 1000))
	}
	if strings.TrimSpace(r.Err) != "" {
		b.WriteString("\n--- stderr ---\n" + truncate(r.Err, 2000))
	}
	if !r.OK {
		return b.String(), fmt.Errorf("python_session 执行出错")
	}
	return b.String(), nil
}

func (s *pySession) kill() error {
	if s.stdin != nil {
		_ = s.stdin.Close()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_, _ = s.cmd.Process.Wait()
	}
	if s.dir != "" {
		_ = os.RemoveAll(s.dir)
	}
	return nil
}
