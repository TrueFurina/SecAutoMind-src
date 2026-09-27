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
func TestMain(m *testing.M) {
	if os.Getenv("SECAUTOMIND_REGISTRY_SWEEP_MS") == "" {
		_ = os.Setenv("SECAUTOMIND_REGISTRY_SWEEP_MS", "60000")
	}
	os.Exit(m.Run())
}
