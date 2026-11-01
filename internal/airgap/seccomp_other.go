//go:build !linux

package airgap

import (
	"fmt"
	"os"
)

// runChild 在非 Linux 平台**拒绝执行**（fail-closed）。
// 断网闸依赖 seccomp，Windows/macOS 上装不了；此时若"假装装好了"继续跑，
// 评测数字会被联网污染且毫无提示 —— 宁可明确失败。
func runChild(target string, args []string) {
	fmt.Fprintf(os.Stderr, "[airgap] 当前平台不支持 seccomp 断网（target=%s），拒绝执行\n", target)
	os.Exit(97)
}
