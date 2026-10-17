package ctfplatform

// ───────────────────────── 真实客户端调用路径断言（无需真机凭证）─────────────────────────
//
// 目的：用 httptest 模拟官方平台，验证 *真实* DasCTFPlatform 客户端（非 fakePlatform 替身）
// 在 CreateInstance / GetAccess / DownloadAttachment 三个生产调用点上：
//   - 命中正确的 HTTP 方法 + 端点路径；
//   - 携带正确的鉴权头（证明凭证从环境变量注入生效）；
//   - 请求体满足官方契约（exerciseId 数值型）；
//   - 能正确解析平台返回（instance_id / exposeIps / 附件落盘）。
// 这把「生产代码有人调用」的证据从「接口层接线」推进到「协议层真实可达」，且不依赖真机凭证。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestRealClientCreateInstanceCallPath 断言 CreateInstance 真实打到 build-exercise-env，
// 方法=POST、鉴权头存在、body 含数值型 exerciseId，并正确解析 instance_id。
func TestRealClientCreateInstanceCallPath(t *testing.T) {
	var mu sync.Mutex
	var gotPath, gotMethod, gotAuth string
	var gotBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotAuth = r.Header.Get("X-Agent-AccessKey")
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &gotBody)
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":"00000","data":{"instance_id":"inst-xyz","status":"running"}}`))
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	p.Token = "test-token-from-env"

	inst, err := p.CreateInstance(context.Background(), "1001")
	if err != nil {
		t.Fatalf("CreateInstance 失败: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotMethod != http.MethodPost {
		t.Errorf("CreateInstance 应为 POST，实际 %s", gotMethod)
	}
	if gotPath != "/slab-match/api/v1/agent/ctf/build-exercise-env" {
		t.Errorf("CreateInstance 端点错误: %s", gotPath)
	}
	if gotAuth != "test-token-from-env" {
		t.Errorf("CreateInstance 未携带鉴权头（凭证注入失效）: %q", gotAuth)
	}
	// 官方契约：exerciseId 必须是数值型
	if n, ok := gotBody["exerciseId"].(float64); !ok || int(n) != 1001 {
		t.Errorf("CreateInstance body.exerciseId 应为数值 1001，实际 %#v", gotBody["exerciseId"])
	}
	if inst.InstanceID != "inst-xyz" {
		t.Errorf("instance_id 解析错误: %q", inst.InstanceID)
	}
	if inst.Status != "running" {
		t.Errorf("instance status 解析错误: %q", inst.Status)
	}
}

// TestRealClientGetAccessCallPath 断言 GetAccess 真实打到 challenge_detail?exerciseId=...，
// 并从 endpoints[].exposeIps 正确提取靶机 host/port。
func TestRealClientGetAccessCallPath(t *testing.T) {
	var mu sync.Mutex
	var gotPath, gotQuery string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		// 真源：靶机地址在 endpoints[].exposeIps[0]（"ip:port"）
		_, _ = w.Write([]byte(`{"code":"00000","data":{"endpoints":[{"name":"web","exposeIps":["1.2.3.4:8080"],"proxyIps":[],"ports":[]}]}}`))
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	acc, err := p.GetAccess(context.Background(), "1001")
	if err != nil {
		t.Fatalf("GetAccess 失败: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotPath != "/slab-match/api/v1/agent/ctf/exercise" {
		t.Errorf("GetAccess 端点错误: %s", gotPath)
	}
	if gotQuery != "exerciseId=1001" {
		t.Errorf("GetAccess query 错误: %q", gotQuery)
	}
	if acc == nil {
		t.Fatal("GetAccess 应返回非 nil Access")
	}
	if acc.Host != "1.2.3.4" {
		t.Errorf("靶机 host 提取错误: %q", acc.Host)
	}
	if acc.Port != 8080 {
		t.Errorf("靶机 port 提取错误: %d", acc.Port)
	}
}

// TestRealClientDownloadAttachmentCallPath 断言 DownloadAttachment 走真实 GetChallenge
// 抽取附件 URL，并把文件落到 chat_uploads/ctf/<题号>/ 白名单下，返回本地路径且内容正确。
func TestRealClientDownloadAttachmentCallPath(t *testing.T) {
	const fileContent = "ATTACHMENT-BINARY-PROBE-2026"

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/slab-match/api/v1/agent/ctf/exercise":
			// challenge_detail：附件 URL 指向同一 server 的 /file.bin
			detail := fmt.Sprintf(
				`{"code":"00000","data":{"id":"1001","has_attachment":true,"attachment":{"url":%q}}}`,
				srv.URL+"/file.bin")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(detail))
		case r.URL.Path == "/file.bin":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(fileContent))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"code":"00000","data":{}}`))
		}
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	// 清理落盘目录（DownloadAttachment 相对 cwd 写 chat_uploads/ctf/1001/）
	defer os.RemoveAll(filepath.Join("chat_uploads", "ctf", "1001"))

	paths, err := p.DownloadAttachment(context.Background(), "1001")
	if err != nil {
		t.Fatalf("DownloadAttachment 失败: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("应落盘 1 个附件，实际 %d: %v", len(paths), paths)
	}
	data, rerr := os.ReadFile(paths[0])
	if rerr != nil {
		t.Fatalf("读取落盘附件失败: %v", rerr)
	}
	if string(data) != fileContent {
		t.Fatalf("落盘内容错误: %q", string(data))
	}
	// 安全约束：路径必须仍在 chat_uploads/ctf/1001/ 之下（用绝对 cwd 比对）
	cwd, _ := os.Getwd()
	whiteRoot := filepath.Clean(filepath.Join(cwd, "chat_uploads", "ctf", "1001"))
	if !strings.HasPrefix(filepath.Clean(paths[0]), whiteRoot) {
		t.Errorf("附件落盘越出白名单目录: %s (期望前缀 %s)", paths[0], whiteRoot)
	}
}

// TestRealClientNilTokenNoAuthHeader 断言未设凭证时绝不发送鉴权头（避免把空 token 当有效值打给平台）。
func TestRealClientNilTokenNoAuthHeader(t *testing.T) {
	var mu sync.Mutex
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("X-Agent-AccessKey")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":"00000","data":{"instance_id":"x"}}`))
	}))
	defer srv.Close()

	p := newTestPlatform(t, srv.URL)
	p.Token = "" // 模拟未配置凭证
	if _, err := p.CreateInstance(context.Background(), "1"); err != nil {
		t.Fatalf("无凭证调用应仍走协议（仅无鉴权头）: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotAuth != "" {
		t.Errorf("未设凭证不应发送鉴权头，实际 %q", gotAuth)
	}
}
