package ctfplatform

// rangeproc_test.go —— 测试用靶场进程清理工具。
//
// 背景（2026-10-21 实测）：靶场用例用 `exec.Command("python", range.py, port)` 起服务，
// 结束时 `cmd.Process.Kill()` 在 Windows 上**不一定杀干净**——实测留下
// `python.exe ssrf_range.py 18220` 持续 LISTENING，导致下一次运行绑不上固定端口，
// 表现为 "靶场未就绪" 或打到陈旧实例（数据不同 → flag 不匹配）。
//
// 对策：① 启动前先清掉占用该端口的残留监听；② 结束时用 taskkill /T /F 杀进程树。

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// killProcessTree 杀掉 pid 及其子进程（Windows 用 taskkill /T，其他平台退回 Kill）。
func killProcessTree(pid int) {
	if pid <= 0 {
		return
	}
	if runtime.GOOS == "windows" {
		_ = exec.Command("taskkill", "/PID", strconv.Itoa(pid), "/T", "/F").Run()
		return
	}
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}

// killPortListeners 杀掉所有正在 LISTEN 指定端口的进程（仅 Windows 实现）。
// 用于"上一轮残留"的防御性清理；取不到就静默跳过，不影响测试语义。
func killPortListeners(port int) {
	if runtime.GOOS != "windows" {
		return
	}
	out, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		return
	}
	target := ":" + strconv.Itoa(port)
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, target) || !strings.Contains(line, "LISTENING") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		pid := f[len(f)-1]
		if seen[pid] || pid == "0" {
			continue
		}
		seen[pid] = true
		_ = exec.Command("taskkill", "/PID", pid, "/T", "/F").Run()
	}
}
