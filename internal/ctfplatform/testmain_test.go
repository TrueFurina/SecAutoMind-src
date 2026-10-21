package ctfplatform

import (
	"os"
	"testing"
)

// TestMain 统一抬高「注册表全量扫描」的超时（仅测试环境）。
//
// 背景（2026-09-28 CI 实锤）：
//   - 生产默认扫描超时 = 6s（presolve_registry.go: registrySweepTimeout）。
//   - 注册表内有 176 个求解器，全量扫描在 CI（共享 runner + `go test -race`，每求解器慢数倍）
//     上跑不完 → 上下文超时 → 扫描被 cancel → 部分求解器（如 Priority 34 的 bin_zip_inner）
//     从未执行 → PresolveResult.Engine 为空、flags 为空。
//   - 现象：TestAttachmentForensicsBenchmark 在 CI 上 9/10（缺 artifact_zip_inner）、耗时 19s；
//     本地（无 race）0.46s 稳定 10/10 → 典型 flaky，且本地无法复现。
//
// 这里只影响测试进程的超时预算，**不改变生产默认值**（生产仍 6s，见 presolve_registry.go）。
// 若需在单个测试内覆盖，用 t.Setenv 即可（优先级更高）。
// testRangePorts 是各靶场用例使用的固定端口。
// 集中列在这里，供 TestMain 启动前做一次性残留清理。
var testRangePorts = []int{18089, 18090, 18095, 18098, 18099, 18220, 18221, 18222, 18223, 18224}

func TestMain(m *testing.M) {
	// 子进程替身（rangeproc_ready_test.go 的 re-exec）直接跑，不做端口清理：
	// 否则每个替身启动都要多花 ~2s 做 10 次 netstat，把「快速失败」测成慢速失败。
	if os.Getenv("RANGEPROC_CHILD_MODE") != "" {
		os.Exit(m.Run())
	}
	if os.Getenv("SECAUTOMIND_REGISTRY_SWEEP_MS") == "" {
		_ = os.Setenv("SECAUTOMIND_REGISTRY_SWEEP_MS", "60000")
	}
	// 启动前清掉上一轮被强杀（如 CI 超时、Ctrl-C）留下的靶场监听。
	// 背景（2026-10-21 实测）：cmd.Process.Kill() 在 Windows 上可能杀不干净，
	// 残留的 python 靶场会占住固定端口，导致后续运行「靶场未就绪」或打到陈旧实例。
	for _, p := range testRangePorts {
		killPortListeners(p)
	}
	os.Exit(m.Run())
}
