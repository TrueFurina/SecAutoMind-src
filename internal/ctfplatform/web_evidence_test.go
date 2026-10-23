package ctfplatform

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"
)

// newCTF4LikeServer 模拟 LAMPSecurity CTF4 的包含行为：
//
//	include($page . ".php")  —— 无 null byte 时补后缀
//	pages/ 为包含根目录      —— 需要足够深度的 ../ 才能到 /
func newCTF4LikeServer(t *testing.T, leak bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		if page == "" {
			io.WriteString(w, `<html><body>
<a href="/?page=blog&title=Blog">Blog</a>
<a href="/?page=research&title=Research">Research</a>
<form action="/?page=search&title=Search" method="post"><input name="searchterm"></form>
</body></html>`)
			return
		}
		if !leak {
			io.WriteString(w, `<html><body><div id="main"></div></body></html>`)
			return
		}
		// 模拟 include($page.".php")：含 NUL 则截断且不补后缀
		name := page
		if i := strings.IndexByte(name, 0); i >= 0 {
			name = name[:i]
		} else {
			name += ".php"
		}
		switch clean := path.Clean("/pages/" + name); clean {
		case "/etc/passwd":
			io.WriteString(w, "root:x:0:0:root:/root:/bin/bash\n"+
				"daemon:x:1:1:daemon:/usr/sbin:/bin/sh\n"+
				"lampsec:x:500:500::/home/lampsec:/bin/bash\n")
		case "/restricted/.htpasswd":
			io.WriteString(w, "ghighland:8RkVRDjjkJhq6\npmoore:xHaymgB2KxbJU\n")
		default:
			io.WriteString(w, `<html><body><div id="main"></div></body></html>`)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestBuildProbeURL_KeepsNullByteLiteral(t *testing.T) {
	got := buildProbeURL("http://h:8080/", "/", "page", "../../../../etc/passwd%00")
	want := "http://h:8080/?page=../../../../etc/passwd%00"
	if got != want {
		t.Fatalf("buildProbeURL = %q, want %q（%%00 不得被二次转义）", got, want)
	}
	// 端点已带 query 时应改用 &
	got2 := buildProbeURL("http://h", "/index.php?a=1", "page", "x")
	if got2 != "http://h/index.php?a=1&page=x" {
		t.Fatalf("buildProbeURL(带 query) = %q", got2)
	}
}

func TestClassifySensitive(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		signal string
		ok     bool
	}{
		{"passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:/bin/sh\n", "etc_passwd", true},
		{"shadow", "root:$6$abc$def:19000:0:99999:7:::\n", "etc_shadow", true},
		{"htpasswd_des", "alice:8RkVRDjjkJhq6\nbob:xHaymgB2KxbJU\n", "htpasswd_hash", true},
		{"htpasswd_apr1", "alice:$apr1$abcdefgh$0123456789abcdef\n", "htpasswd_hash", true},
		{"normal_page", `<html><body>hello world</body></html>`, "", false},
		{"root_word_only", "the root of the problem", "", false},
	}
	for _, c := range cases {
		sig, detail, ok := classifySensitive([]byte(c.body))
		if ok != c.ok || sig != c.signal {
			t.Errorf("%s: got (%q,%v), want (%q,%v) detail=%q", c.name, sig, ok, c.signal, c.ok, detail)
		}
	}
}

func TestProbeSensitiveFileRead_DetectsPasswd(t *testing.T) {
	srv := newCTF4LikeServer(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ev := ProbeSensitiveFileRead(ctx, srv.URL, WebHints{Params: []string{"page"}, Endpoints: []string{"/"}})
	if len(ev) == 0 {
		t.Fatalf("应检出敏感文件读取，实际 0 条")
	}
	found := false
	for _, e := range ev {
		if e.Signal == "etc_passwd" {
			found = true
			if e.Kind != "lfi_sensitive_file" || e.Param != "page" {
				t.Errorf("证据字段异常: %+v", e)
			}
			if !strings.Contains(e.Payload, "%00") {
				t.Errorf("应使用 null-byte 截断载荷，实际 %q", e.Payload)
			}
			if strings.Contains(e.Detail, "8RkVRDjjkJhq6") {
				t.Errorf("Detail 泄漏了口令哈希: %q", e.Detail)
			}
		}
	}
	if !found {
		t.Fatalf("未检出 etc_passwd，证据: %+v", ev)
	}
}

func TestProbeSensitiveFileRead_DetectsHtpasswd(t *testing.T) {
	srv := newCTF4LikeServer(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ev := ProbeSensitiveFileRead(ctx, srv.URL, WebHints{
		Params:    []string{"page"},
		Endpoints: []string{"/"},
		Payloads:  []string{"../../restricted/.htpasswd%00"},
	})
	found := false
	for _, e := range ev {
		if e.Signal == "htpasswd_hash" {
			found = true
			if !strings.Contains(e.Detail, "DES-crypt") {
				t.Errorf("应识别 DES-crypt，实际 %q", e.Detail)
			}
		}
	}
	if !found {
		t.Fatalf("未检出 htpasswd_hash，证据: %+v", ev)
	}
}

func TestProbeSensitiveFileRead_NoFalsePositive(t *testing.T) {
	srv := newCTF4LikeServer(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if ev := ProbeSensitiveFileRead(ctx, srv.URL, WebHints{}); len(ev) != 0 {
		t.Fatalf("不应产生误报，实际 %+v", ev)
	}
}

func TestDiscoverWebParams(t *testing.T) {
	srv := newCTF4LikeServer(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	eps, params := DiscoverWebParams(ctx, srv.URL)
	if len(params) == 0 {
		t.Fatalf("应发现参数名，实际 0")
	}
	hasPage := false
	for _, p := range params {
		if p == "page" {
			hasPage = true
		}
	}
	if !hasPage {
		t.Fatalf("未发现 page 参数，实际 %v", params)
	}
	if len(eps) == 0 {
		t.Fatalf("应发现端点，实际 0")
	}
}
