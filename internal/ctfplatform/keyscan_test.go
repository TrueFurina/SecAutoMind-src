package ctfplatform

import "testing"

// 真实靶机的 `ls -l` 输出片段（已脱敏，保留形态）。
const sampleLS = `-rw-rw-r-- 1 achen achen 843 Mar  9  2009 /home/achen/.ssh/achen_priv.ppk
-rw-rw-r-- 1 achen achen 294 Mar  9  2009 /home/achen/.ssh/achen_pub.ppk
-rwx------ 1 achen achen 226 Mar  9  2009 /home/achen/.ssh/authorized_keys
-rw------- 1 root  root  1675 Mar  9  2009 /home/achen/.ssh/id_rsa
-rw-r--r-- 1 bob   bob   887 Mar  9  2009 /home/bob/.ssh/id_rsa
lrwxrwxrwx 1 achen achen  13 Mar 10  2009 /home/achen/.ssh/link
-rw-r--r-- 1 carol carol 500 Mar  9  2009 /home/carol/.ssh/config
`

func TestParseReadableKeys(t *testing.T) {
	got := parseReadableKeys(sampleLS)
	if len(got) != 2 {
		t.Fatalf("应只保留 2 个可读私钥，实际 %d: %+v", len(got), got)
	}
	// 第一个：achen 的 ppk（其他用户可读）
	if got[0].Path != "/home/achen/.ssh/achen_priv.ppk" || got[0].Owner != "achen" {
		t.Errorf("第一条异常: %+v", got[0])
	}
	// 第二个：bob 的 id_rsa（-rw-r--r-- 可读）
	if got[1].Path != "/home/bob/.ssh/id_rsa" || got[1].Owner != "bob" {
		t.Errorf("第二条异常: %+v", got[1])
	}
	// 明确排除项
	for _, k := range got {
		switch {
		case k.Path == "/home/achen/.ssh/authorized_keys":
			t.Error("authorized_keys 不应被当作私钥")
		case k.Path == "/home/achen/.ssh/achen_pub.ppk":
			t.Error("公钥不应被当作私钥")
		case k.Path == "/home/achen/.ssh/id_rsa":
			t.Error("仅属主可读（-rw-------）的私钥不应入选")
		case k.Path == "/home/carol/.ssh/config":
			t.Error("config 不是私钥")
		case k.Path == "/home/achen/.ssh/link":
			t.Error("符号链接不应入选")
		}
	}
}

func TestParseReadableKeys_EmptyAndGarbage(t *testing.T) {
	for _, in := range []string{"", "total 40\n", "ls: cannot access '/home/*/.ssh/*': No such file or directory\n"} {
		if got := parseReadableKeys(in); len(got) != 0 {
			t.Errorf("输入 %q 应返回空，实际 %+v", in, got)
		}
	}
}

func TestParseReadableKeys_Dedupe(t *testing.T) {
	line := "-rw-r--r-- 1 bob bob 887 Mar  9  2009 /home/bob/.ssh/id_rsa"
	got := parseReadableKeys(line + "\n" + line)
	if len(got) != 1 {
		t.Fatalf("同一路径应去重，实际 %d 条", len(got))
	}
}

func TestLooksLikePrivateKey(t *testing.T) {
	yes := []string{
		"/home/a/.ssh/a_priv.ppk", "/home/a/.ssh/id_rsa", "/x/server.key",
		"/x/cert.pem", "/x/id_ed25519",
	}
	no := []string{
		"/home/a/.ssh/a_pub.ppk", "/home/a/.ssh/authorized_keys",
		"/home/a/.ssh/known_hosts", "/home/a/.ssh/config", "/x/notes.txt",
	}
	for _, p := range yes {
		if !looksLikePrivateKey(p) {
			t.Errorf("%q 应判定为私钥", p)
		}
	}
	for _, p := range no {
		if looksLikePrivateKey(p) {
			t.Errorf("%q 不应判定为私钥", p)
		}
	}
}
