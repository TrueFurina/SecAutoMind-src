package ctfplatform

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRunKillChain_StopsAtReconOnBadURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	res := RunKillChain(ctx, KillChainOptions{
		BaseURL:       "http://127.0.0.1:1/", // 必然连不上
		SSHAddr:       "127.0.0.1:1",
		AllowInsecure: true,
		StepTimeout:   2 * time.Second,
	})
	if len(res.Steps) != 1 {
		t.Fatalf("应在 recon 一步即停，实际走了 %d 步: %+v", len(res.Steps), res.Steps)
	}
	if res.Steps[0].OK {
		t.Fatal("recon 不应成功")
	}
	if res.Root {
		t.Fatal("不应误报已到 root")
	}
	if s := res.Summary(); !strings.Contains(s, "0/1") || !strings.Contains(s, "未到 root") {
		t.Errorf("Summary 异常: %q", s)
	}
}

func TestRunKillChain_EmptyOptionsDoesNotPanic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res := RunKillChain(ctx, KillChainOptions{StepTimeout: time.Second})
	if res == nil {
		t.Fatal("结果不应为 nil")
	}
	if res.Root {
		t.Fatal("空参数不应判定为 root")
	}
	// 必须给出可读的失败原因，而不是静默返回
	if len(res.Steps) == 0 || res.Steps[0].Detail == "" {
		t.Fatalf("应记录失败原因，实际: %+v", res.Steps)
	}
}

func TestKillChainResult_Summary(t *testing.T) {
	r := &KillChainResult{
		Steps: []ChainStep{
			{Name: "recon", OK: true},
			{Name: "loot", OK: true},
			{Name: "crack", OK: false},
		},
	}
	if s := r.Summary(); !strings.Contains(s, "2/3") || !strings.Contains(s, "未到 root") {
		t.Errorf("Summary = %q", s)
	}
	r.Root = true
	if s := r.Summary(); !strings.Contains(s, "已到 root") {
		t.Errorf("Summary = %q", s)
	}
}

// TestLiveKillChain 活靶机跑完整链条，断言到达 root。
//
//	CTF4_LAB_URL=http://127.0.0.1:8080/
//	CTF4_SSH_ADDR=127.0.0.1:2222
//	CTF4_WORDLIST=D:/tmp_gotest/words.txt      （可选；给了 CTF4_SSH_USER/PASS 可跳过破解）
//	CTF4_SSH_USER / CTF4_SSH_PASS              （可选）
func TestLiveKillChain(t *testing.T) {
	base, sshAddr := os.Getenv("CTF4_LAB_URL"), os.Getenv("CTF4_SSH_ADDR")
	if base == "" || sshAddr == "" {
		t.Skip("未设 CTF4_LAB_URL / CTF4_SSH_ADDR，跳过")
	}

	opts := KillChainOptions{
		BaseURL:       base,
		SSHAddr:       sshAddr,
		KnownUser:     os.Getenv("CTF4_SSH_USER"),
		KnownPassword: os.Getenv("CTF4_SSH_PASS"),
		AllowInsecure: true,
		StepTimeout:   30 * time.Second,
	}
	if dict := os.Getenv("CTF4_WORDLIST"); dict != "" {
		words, err := LoadWordlist(dict)
		if err != nil {
			t.Fatalf("读字典失败: %v", err)
		}
		opts.Wordlist = words
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Second)
	defer cancel()

	start := time.Now()
	res := RunKillChain(ctx, opts)
	t.Logf("[killchain] 总耗时 %v，%s", time.Since(start).Round(time.Second), res.Summary())
	for i, s := range res.Steps {
		mark := "OK  "
		if !s.OK {
			mark = "FAIL"
		}
		t.Logf("  %d. [%s] %-10s %v  %s", i+1, mark, s.Name, s.Elapsed, s.Detail)
	}
	if !res.Root {
		t.Fatalf("未到达 root，停在 %q", res.Steps[len(res.Steps)-1].Name)
	}
	if !strings.Contains(res.RootID, "uid=0(root)") {
		t.Errorf("RootID 异常: %q", res.RootID)
	}
}
