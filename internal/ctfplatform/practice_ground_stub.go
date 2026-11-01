// practice_ground_stub.go —— CTF² 练习场加载/提交的最小桩（2026-11-02 立尺补）。
//
// 背景：cmd/evalharness 的 --practice 分支引用 LoadPracticeChallenges/
// SubmitPracticeFlag，但其实现从未入树（引用方先行的在飞 WIP，红测试持续
// 未自愈 → 全仓 build 断，周审红测试核验 FAIL）。本桩让 build 恢复绿。
//
// 🔴 归属与替换：本文件是**立尺代打的编译恢复桩**，不是实现。实现归属
// evalharness 引用方会话（Dream 线）——收口时以真实现**整文件替换或删除本桩**
// 并接上 CTF² 练习场 API。桩语义 fail-closed：加载返回明确错误（不伪造题单），
// 提交返回错误（不伪造 accepted=true）——CI 里 --practice 分支会打印
// [ERR] 加载练习场失败 并退出，不会静默产出假报告。
package ctfplatform

import (
	"context"
	"errors"
)

var ErrPracticeGroundStub = errors.New(
	"practice ground: 编译恢复桩（立尺 2026-11-02）——真实现待 evalharness 引用方会话落地；" +
		"在真实现入树前，--practice 模式不可用（fail-closed，不产出假评测报告）")

// LoadPracticeChallenges 桩：始终返回错误（不伪造题单）。
func LoadPracticeChallenges(ctx context.Context, ground string) ([]Challenge, error) {
	return nil, ErrPracticeGroundStub
}

// SubmitPracticeFlag 桩：始终返回错误（不伪造 accepted）。
func SubmitPracticeFlag(ctx context.Context, ground, challengeID, flag string) (bool, error) {
	return false, ErrPracticeGroundStub
}
