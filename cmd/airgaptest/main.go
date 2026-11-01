// Command airgaptest 是断网闸（package airgap）的**唯一可信自检**。
//
// 为什么需要它：2026-11-01 实测发现，历史上所有"断网跑批"的日志里，
// 模型只尝试过域名，拿到的错误是 `Temporary failure in name resolution`。
// 这个错误与"这台机器没配 DNS"完全同形 —— 无法证明 seccomp 生效。
// 更糟的是 `eval_m4_airgap.log` 名字带 airgap，而 `cmd/evalharness`
// 压根没接 airgap，模型在里面成功下载了 GitHub 上的二进制。
//
// 判定规则（必须用 IP 直连，绕开 DNS）：
//
//	基线（不开闸）：AF_INET 应当 CONNECTED-NOT-BLOCKED
//	开闸（CTF_AIRGAP=1）：AF_INET 应当是 PermissionError errno=1 (EPERM)
//	                      AF_UNIX 必须仍然 OK（不能误伤本地 IPC）
//
// 若开闸后报的是 ENETUNREACH(101) 或 DNS 失败，都不算通过 —— 那是环境问题，
// 不是闸门生效。跑批前用它自检，输出贴进跑批日志。
package main

import (
	"fmt"
	"os"
	"os/exec"

	"secautomind-ai/internal/airgap"
)

const probe = `import socket
for fam, addr in [("AF_INET", "1.1.1.1"), ("AF_INET6", "2606:4700:4700::1111")]:
    try:
        fam_const = socket.AF_INET6 if fam == "AF_INET6" else socket.AF_INET
        s = socket.socket(fam_const, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((addr, 80))
        print(fam, "CONNECTED-NOT-BLOCKED")
        s.close()
    except Exception as e:
        print(fam, type(e).__name__, getattr(e, "errno", None), e)
try:
    a, b = socket.socketpair()
    print("AF_UNIX", "OK")
    a.close(); b.close()
except Exception as e:
    print("AF_UNIX", "FAIL", e)
try:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("AF_INET-UDP", "OK")
    u.close()
except Exception as e:
    print("AF_INET-UDP", type(e).__name__, getattr(e, "errno", None), e)
`

func main() {
	airgap.RegisterMain()
	airgap.MaybeRunChild()

	fmt.Printf("[airgaptest] CTF_AIRGAP=%q Enabled=%v IsChild=%v\n",
		os.Getenv("CTF_AIRGAP"), airgap.Enabled(), airgap.IsChild())

	cmd := exec.Command("python3", "-c", probe)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	airgap.Wrap(cmd)
	if err := cmd.Run(); err != nil {
		fmt.Println("[airgaptest] run err =", err)
		os.Exit(1)
	}
}
