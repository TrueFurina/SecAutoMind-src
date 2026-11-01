//go:build linux

package pyskill

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"secautomind-ai/internal/airgap"
	"secautomind-ai/internal/ctfplatform"
)

// TestMain 让测试二进制能充当 airgap 包装层（Wrap 会 re-exec 自己）。
func TestMain(m *testing.M) {
	airgap.RegisterMain()
	airgap.MaybeRunChild()
	os.Exit(m.Run())
}

// canarySkill：从 params["url"] 抓一个地址，只把 sha256 写进结果文件。
//
// 为什么不直接抓 GitHub：服务器对外网**本来就不通**（实测 URLError），
// 那样即使"开闸后被拦"也证明不了闸门 —— 环境断网和 seccomp 断网在结果上一样。
// 改用 127.0.0.1 上的临时监听做靶子：网络栈本身是通的，唯一变量就是 seccomp。
// 同时区分异常类型：PermissionError = 内核拒绝（闸门），URLError = 网络不可达（环境）。
const canarySkill = `
import hashlib, json

def run(params):
    out = params.get("out") or "canary_sha.txt"
    url = params.get("url") or ""
    try:
        import urllib.request
        body = urllib.request.urlopen(url, timeout=10).read()
        status, digest = "FETCHED", hashlib.sha256(body).hexdigest()
    except Exception as e:
        cause = getattr(e, "reason", e)
        status, digest = "BLOCKED:" + type(cause).__name__, ""
    with open(out, "w") as f:
        f.write(status + " " + digest)
    return {"ok": True, "status": status}
`

func setupCanary(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	skills := filepath.Join(dir, "skills")
	if err := os.MkdirAll(skills, 0o755); err != nil {
		t.Fatalf("建 skills 目录失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skills, "leak_canary.py"), []byte(canarySkill), 0o644); err != nil {
		t.Fatalf("写 canary skill 失败: %v", err)
	}
	t.Setenv("CTF_SKILLS_DIR", skills)
}

// runCanary 跑一次 skill，返回结果文件内容（"<status> <sha256>"）。
func runCanary(t *testing.T, url string) string {
	t.Helper()
	wd := t.TempDir()
	out := filepath.Join(wd, "canary_sha.txt")
	r := New(context.Background(), zap.NewNop())
	ch := &ctfplatform.Challenge{ID: "canary", Title: "canary", Category: "crypto"}
	_, _ = r.runSkillWith(context.Background(), "leak_canary", ch, map[string]any{"out": out, "url": url})
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("canary 未产出结果文件（skill 根本没跑起来？）: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// 端到端金丝雀：证明"产品真实子进程路径"确实能/不能把远端内容抓进来。
//
// 覆盖的是**组合**：pyskill → execSkillSubprocess → airgap.Wrap → seccomp。
// 单测只证明 seccomp 有效，审计只证明公开仓库里有真值；两者能否合成一条通路，
// 必须真跑才知道（本项目多次栽在"两个绿不合成"）。
func TestAirgapBlocksOutboundFetchFromSkill(t *testing.T) {
	setupCanary(t)

	body := []byte("canary-payload-not-a-real-flag\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])

	t.Run("airgap_off_must_fetch", func(t *testing.T) {
		t.Setenv("CTF_AIRGAP", "")
		got := runCanary(t, srv.URL)
		if !strings.HasPrefix(got, "FETCHED") {
			t.Skipf("靶子不可达（%s）—— 无法作为阳性对照，本用例不下结论", got)
		}
		if !strings.Contains(got, want) {
			t.Fatalf("抓到的内容与靶子不一致: %s", got)
		}
		t.Log("阳性对照成立：未开闸时 skill 子进程能把远端内容读进来")
	})

	t.Run("airgap_on_must_block_with_eperm", func(t *testing.T) {
		t.Setenv("CTF_AIRGAP", "1")
		got := runCanary(t, srv.URL)
		if !strings.HasPrefix(got, "BLOCKED:PermissionError") {
			// 关键区分：URLError/gaierror = 环境或 DNS 问题，不能算闸门生效。
			t.Fatalf("期望 BLOCKED:PermissionError（内核 EPERM），实际: %s", got)
		}
		t.Logf("闸门生效：%s", got)
	})
}
