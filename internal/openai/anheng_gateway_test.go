package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"secautomind-ai/internal/config"
)

// 安恒 AI 安全网关（规划 §4.6）在 SecAutoMind 里**不是独立组件**，而是作为
// **OpenAI 兼容通道**接入：config.OpenAIConfig{BaseURL, APIKey, Model}。
// 因此这两条测试锁的是该接入方式的两条底线，而不是某个专属 driver：
//
//	TestAnhengGateway_Connect —— 配好 base_url 后能连通、能取到模型列表。
//	TestAnhengGateway_Degrade —— 网关 5xx / 不可达 / 无凭证时 **fail-closed**：
//	                              必须显式报错，绝不能静默"成功"返回未验证结果。
//
// 🔴 诚实边界（不得删除，避免被当真机证据）：
//   下述 connect/degrade 主体均基于 httptest **模拟**网关，**不等于安恒官方网关真机联调**。
//   TestAnhengGateway_Connect 末尾有"真机段"，仅当配置了 secret
//   （ANHENG_GATEWAY_BASE_URL / ANHENG_GATEWAY_API_KEY）时执行；未配置即 Skip。
//   在该段真正跑通之前，对外材料必须保持"预留接入"措辞（规划 §4.6 明文要求）。

const anhengMockModelsBody = `{"object":"list","data":[{"id":"anheng-sec-1","object":"model"}]}`

// anhengMockGateway 起一个最小的 OpenAI 兼容模拟网关。
// 它会校验 Bearer 鉴权头：缺失则 401 —— 这样"客户端是否真的带上了凭证"也被覆盖到，
// 否则一个把 APIKey 丢掉不发的实现也能骗过连通性测试。
func anhengMockGateway(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"missing bearer"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestAnhengGateway_Connect(t *testing.T) {
	srv := anhengMockGateway(t, http.StatusOK, anhengMockModelsBody)
	defer srv.Close()

	c := NewClient(&config.OpenAIConfig{
		BaseURL: srv.URL,
		APIKey:  "test-key-not-a-real-credential",
		Model:   "anheng-sec-1",
	}, srv.Client(), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	models, err := c.ListModels(ctx)
	if err != nil {
		t.Fatalf("模拟网关应连通，却失败: %v", err)
	}
	if len(models) != 1 || models[0] != "anheng-sec-1" {
		t.Fatalf("未取到预期模型列表: %v", models)
	}

	// ── 真机段（无 secret 则 Skip）─────────────────────────────
	base := strings.TrimSpace(os.Getenv("ANHENG_GATEWAY_BASE_URL"))
	key := strings.TrimSpace(os.Getenv("ANHENG_GATEWAY_API_KEY"))
	if base == "" || key == "" {
		t.Log("SKIP 真机段：未配置 ANHENG_GATEWAY_BASE_URL / ANHENG_GATEWAY_API_KEY。" +
			"模拟层已通过，但这**不等于**安恒网关真机联调通过 —— 材料须保持『预留接入』措辞。")
		return
	}
	real := NewClient(&config.OpenAIConfig{BaseURL: base, APIKey: key},
		&http.Client{Timeout: 20 * time.Second}, nil)
	if _, err := real.ListModels(ctx); err != nil {
		t.Fatalf("安恒网关真机连通失败: %v", err)
	}
	t.Log("安恒网关真机连通成功 —— 可将材料措辞由『预留接入』升为『已对接』")
}

func TestAnhengGateway_Degrade(t *testing.T) {
	// ① 网关 5xx：必须返回 error，不得静默成功（对安全智能体尤其致命：
	//    静默成功会把"没分析成"伪装成"分析完了没问题"）。
	t.Run("网关5xx必须fail-closed", func(t *testing.T) {
		srv := anhengMockGateway(t, http.StatusBadGateway, `{"error":"gateway down"}`)
		defer srv.Close()
		c := NewClient(&config.OpenAIConfig{BaseURL: srv.URL, APIKey: "k"}, srv.Client(), nil)
		if _, err := c.ListModels(context.Background()); err == nil {
			t.Fatal("网关 502 时必须返回错误，实际却成功（静默降级）")
		}
	})

	// ② 网关不可达：连接失败必须显式报错。
	t.Run("网关不可达必须fail-closed", func(t *testing.T) {
		dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		deadURL := dead.URL
		dead.Close() // 关闭后端口不再监听
		c := NewClient(&config.OpenAIConfig{BaseURL: deadURL, APIKey: "k"},
			&http.Client{Timeout: 3 * time.Second}, nil)
		if _, err := c.ListModels(context.Background()); err == nil {
			t.Fatal("网关不可达时必须返回错误，实际却成功")
		}
	})

	// ③ 无凭证：本地即拒（不应发起请求）。
	t.Run("无凭证必须fail-closed", func(t *testing.T) {
		c := NewClient(&config.OpenAIConfig{BaseURL: "http://127.0.0.1:1", APIKey: ""}, nil, nil)
		_, err := c.ListModels(context.Background())
		if err == nil {
			t.Fatal("未配置 APIKey 时必须返回错误，实际却成功")
		}
		if !strings.Contains(err.Error(), "api key is empty") {
			t.Fatalf("期望『api key is empty』类错误，实际: %v", err)
		}
	})

	// ④ 网关返回 401（凭证失效/被吊销）：也必须是明确错误。
	//    注意这里凭证是**非空**的，走的是"发出请求、网关拒绝"路径
	//    （与 ③ 的"本地即拒"是两回事，别合并）。
	t.Run("凭证失效必须fail-closed", func(t *testing.T) {
		srv := anhengMockGateway(t, http.StatusUnauthorized, `{"error":"invalid api key"}`)
		defer srv.Close()
		c := NewClient(&config.OpenAIConfig{BaseURL: srv.URL, APIKey: "expired-key"},
			srv.Client(), nil)
		if _, err := c.ListModels(context.Background()); err == nil {
			t.Fatal("网关 401 时必须返回错误，实际却成功")
		}
	})
}
