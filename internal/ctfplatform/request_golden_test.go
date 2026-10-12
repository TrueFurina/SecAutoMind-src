package ctfplatform

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"go.uber.org/zap"
)

// ── 请求侧双语言一致性 golden ────────────────────────────────────────────
//
// 真值来源：scripts/gen_request_golden.py —— 让西湖论剑真源（Python）客户端
// 真实打出「拉题 → 详情 → 起靶机 → 提交 → 回收」全流程，把实际报文录成 golden。
//
// 与 protocol_golden_test.go 的分工：
//   - protocol_golden_test.go：验证「怎么解读平台返回」（解析侧）
//   - 本文件：验证「怎么向平台发请求」（请求侧：端点、查询参数、鉴权头、请求体）
//
// golden 由真源生成，禁止手改。

const parityToken = "SYNTHETIC-TOKEN-FOR-PARITY-ONLY"

// sourceOnlyEndpoints：真源有、Go 客户端刻意未实现的端点（需随代码演进而更新）。
// openapi：真源用于 OpenAPI 自描述发现，Go 客户端使用静态端点表，不发起该请求。
var sourceOnlyEndpoints = map[string]string{
	"openapi": "真源用于 OpenAPI 自描述发现；Go 侧用静态端点表，刻意不实现",
}

type goldenRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   map[string]string `json:"query"`
	Headers map[string]string `json:"headers"`
	JSON    interface{}       `json:"json"`
}

type requestGolden struct {
	Endpoints map[string]string `json:"endpoints"`
	Requests  []goldenRequest   `json:"requests"`
}

func loadRequestGolden(t *testing.T) requestGolden {
	t.Helper()
	path := filepath.Join("testdata", "request_golden.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 golden 失败（先跑 scripts/gen_request_golden.py）: %v", err)
	}
	var g requestGolden
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatalf("解析 golden 失败: %v", err)
	}
	return g
}

// parityResponses 与真源 generator 的 RESPONSES 保持一致：
// 只需让两侧客户端走完同一条流程，不追求语义完整。
var parityResponses = map[string]string{
	"/slab-match/api/v1/agent/ctf/exercise-list":        `{"code":"00000","data":[{"id":1,"name":"分类容器","corpus":[{"id":1001,"name":"web-01"}]}]}`,
	"/slab-match/api/v1/agent/ctf/exercise":             `{"code":"00000","data":{"id":1001,"name":"web-01","endpoints":[]}}`,
	"/slab-match/api/v1/agent/ctf/build-exercise-env":   `{"code":"00000","data":{"instance_id":"inst-1","status":"running"}}`,
	"/slab-match/api/v1/agent/answer-panel/answer":      `{"code":"00000","data":{"isCorrect":true,"message":"ok"}}`,
	"/slab-match/api/v1/agent/ctf/recover-exercise-env": `{"code":"00000","data":{}}`,
}

// recordedRequest 记录 Go 客户端实际发出的报文（字段与 golden 对齐）。
type recordedRequest struct {
	Method  string
	Path    string
	Query   map[string]string
	Headers map[string]string
	JSON    interface{}
}

func newParityRecorder(recorded *[]recordedRequest) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body interface{}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &body)
		}
		q := map[string]string{}
		for k, v := range r.URL.Query() {
			if len(v) > 0 {
				q[k] = v[0]
			}
		}
		headers := map[string]string{}
		for _, h := range []string{"x-agent-accesskey", "content-type", "user-agent"} {
			if v := r.Header.Get(h); v != "" {
				headers[h] = v
			}
		}
		*recorded = append(*recorded, recordedRequest{
			Method:  r.Method,
			Path:    r.URL.Path,
			Query:   q,
			Headers: headers,
			JSON:    body,
		})
		payload, ok := parityResponses[r.URL.Path]
		if !ok {
			payload = `{"code":"00000","data":{}}`
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}))
}

// TestRequestParityGolden 断言 Go 客户端发出的请求与真源逐项一致。
func TestRequestParityGolden(t *testing.T) {
	g := loadRequestGolden(t)

	var recorded []recordedRequest
	srv := newParityRecorder(&recorded)
	defer srv.Close()

	p := NewDasCTFPlatform(srv.URL, parityToken, zap.NewNop())
	p.listCacheTTL = 0 // 关掉列表 TTL 缓存，确保请求真实发出（与真源 generator 同处理）

	ctx := context.Background()
	_, _ = p.ListChallenges(ctx)
	_, _ = p.GetChallenge(ctx, "1001")
	_, _ = p.CreateInstance(ctx, "1001")
	_, _ = p.SubmitFlag(ctx, "1001", "flag{abc_123}")
	_, _ = p.SubmitFlag(ctx, "nonnumeric-id", "flag{xyz_789}")
	_ = p.ResetInstance(ctx, "1001")

	// ── 端点表 ──
	var sourceOnly []string
	for k, v := range g.Endpoints {
		got, ok := p.Endpoints[k]
		if !ok {
			if _, allowed := sourceOnlyEndpoints[k]; allowed {
				sourceOnly = append(sourceOnly, k)
				continue
			}
			t.Errorf("端点缺失: %s（真源路径 %s）", k, v)
			continue
		}
		if got != v {
			t.Errorf("端点路径不一致 %s: 真源=%s Go=%s", k, v, got)
		}
	}
	var goOnly []string
	for k, v := range p.Endpoints {
		if _, ok := g.Endpoints[k]; !ok {
			goOnly = append(goOnly, k+"="+v)
		}
	}
	if len(goOnly) > 0 {
		sort.Strings(goOnly)
		t.Errorf("Go 存在真源没有的端点（单边漂移）: %v", goOnly)
	}
	sort.Strings(sourceOnly)
	if !reflect.DeepEqual(sourceOnly, []string{"openapi"}) {
		t.Errorf("source-only 端点集合变化（当前 %v），请复核 sourceOnlyEndpoints 是否仍成立", sourceOnly)
	}

	// ── 请求序列 ──
	if len(recorded) != len(g.Requests) {
		t.Fatalf("请求条数不一致: 真源=%d Go=%d", len(g.Requests), len(recorded))
	}
	for i, want := range g.Requests {
		got := recorded[i]
		if got.Method != want.Method {
			t.Errorf("请求[%d] 方法: 真源=%s Go=%s", i, want.Method, got.Method)
		}
		if got.Path != want.Path {
			t.Errorf("请求[%d] 路径: 真源=%s Go=%s", i, want.Path, got.Path)
		}
		if !reflect.DeepEqual(got.Query, normalizeQuery(want.Query)) {
			t.Errorf("请求[%d] 查询参数: 真源=%v Go=%v", i, want.Query, got.Query)
		}
		for h, wv := range want.Headers {
			if gv, ok := got.Headers[h]; !ok || gv != wv {
				t.Errorf("请求[%d] 请求头 %s: 真源=%q Go=%q", i, h, wv, got.Headers[h])
			}
		}
		for h, gv := range got.Headers {
			if _, ok := want.Headers[h]; !ok {
				t.Errorf("请求[%d] 多出请求头 %s=%q（真源未发）", i, h, gv)
			}
		}
		wj, _ := json.Marshal(want.JSON)
		gj, _ := json.Marshal(got.JSON)
		if string(wj) != string(gj) {
			t.Errorf("请求[%d] 请求体: 真源=%s Go=%s", i, wj, gj)
		}
	}
}

func normalizeQuery(q map[string]string) map[string]string {
	if q == nil {
		return map[string]string{}
	}
	return q
}
