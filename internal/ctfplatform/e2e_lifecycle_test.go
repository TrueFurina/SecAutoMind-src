package ctfplatform

// e2e_lifecycle_test.go —— 平台层端到端生命周期契约（验收清单第 1 条）。
//
// 对应 docs/规划-移植与优化总纲.md §7 验收标准第 1 条：
//
//	`go test ./internal/ctfplatform/... -run E2E -v` 全绿（平台层真跑通）
//
// 本文件把「拉题 → 起靶机 → 取访问地址 → 提交 flag → 校验 accepted → 回收靶机」
// 这条参赛资格链路**串成一条**并逐段锁死协议契约（端点路径 / 请求体 / accepted 判据 /
// flag 外壳剥离）。既有 rehearsal_test.go 做的是多场景演练与压力/并发，本文件做的是
// 单一资格线契约串跑，二者分工不同、不互为替代。
//
// 🔴 诚实标注（勿夸大，勿让本文件被当成真机证据）：
// 本测试用 httptest 模拟官方 API，**不等于官方仿真平台真机联调**。规划 §6 风险表明确
// 要求「W1 内必须在官方仿真平台实测一次；单测不可替代」。本文件只负责把链路契约锁进 CI
// 防回归；真机联调仍是独立且未闭环的待办项，不得引用本测试宣称"已真机跑通"。

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// e2eRecorder 记录模拟平台侧收到的全部请求，供断言回放。
type e2eRecorder struct {
	mu           sync.Mutex
	paths        []string         // 命中路径（含查询串）
	submitBodies []map[string]any // 提交请求体
	buildBodies  []map[string]any // 起靶机请求体
	recoverCalls int              // 回收/重置端点调用次数
	correctFlag  string           // 模拟平台认定的正确 flag（去外壳后）
}

func (r *e2eRecorder) record(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paths = append(r.paths, path)
}

func (r *e2eRecorder) snapshotPaths() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.paths))
	copy(out, r.paths)
	return out
}

func (r *e2eRecorder) countPath(path string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, p := range r.paths {
		if p == path {
			n++
		}
	}
	return n
}

// newE2EServer 构造模拟官方 API 的 httptest 服务器。
// 端点路径与 defaultEndpoints 逐字对齐——路径错一条即资格线不成立，故由测试强制锁定。
func newE2EServer(t *testing.T, rec *e2eRecorder) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	full := func(w http.ResponseWriter, code string, data string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":"` + code + `","data":` + data + `}`))
	}

	// ① 拉题：exercise-list
	mux.HandleFunc(defaultEndpoints["challenges"], func(w http.ResponseWriter, r *http.Request) {
		rec.record(r.URL.String())
		full(w, "00000", `[{"id":"1001","title":"E2E 真题","category":"misc",`+
			`"description":"flag 藏在描述里","has_instance":true,"score":100}]`)
	})

	// ② 起靶机：build_env
	mux.HandleFunc(defaultEndpoints["build_env"], func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		rec.mu.Lock()
		rec.buildBodies = append(rec.buildBodies, m)
		rec.mu.Unlock()
		rec.record(r.URL.String())
		full(w, "00000", `{"instance_id":"inst-777","status":"running"}`)
	})

	// ③ 取访问地址：challenge_detail（带 exerciseId 查询串；真源踩坑点是传 instanceId）
	mux.HandleFunc(defaultEndpoints["challenge_detail"], func(w http.ResponseWriter, r *http.Request) {
		rec.record(r.URL.String())
		full(w, "00000", `{"id":"1001","endpoints":[{"name":"web","exposeIps":["10.20.30.40:8080"]}]}`)
	})

	// ④ 提交 flag：answer
	mux.HandleFunc(defaultEndpoints["submit"], func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		rec.mu.Lock()
		rec.submitBodies = append(rec.submitBodies, m)
		correct := rec.correctFlag
		rec.mu.Unlock()
		rec.record(r.URL.String())

		got, _ := m["flag"].(string)
		isCorrect := got == correct
		data := `{"isCorrect":` + boolJSON(isCorrect) + `,"remainingAttempts":4`
		if isCorrect {
			data += `,"message":"accepted"}`
		} else {
			data += `,"message":"wrong flag"}`
		}
		full(w, "00000", data)
	})

	// ⑤ 回收：recover_env（DestroyInstance 复用该端点）
	mux.HandleFunc(defaultEndpoints["recover_env"], func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.recoverCalls++
		rec.mu.Unlock()
		rec.record(r.URL.String())
		full(w, "00000", `{}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func boolJSON(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestPlatformE2E_Lifecycle 是「真实赛场竞争力」维度的资格线串跑。
//
// 断言分两层：
//   - 链路层：每一步都真的发出请求、命中预期端点、拿到预期结果；
//   - 契约层：请求体/判据与官方协议一致（外壳剥离、accepted = 业务码成功 && isCorrect）。
func TestPlatformE2E_Lifecycle(t *testing.T) {
	rec := &e2eRecorder{correctFlag: "real_flag_123"}
	srv := newE2EServer(t, rec)

	p := NewDasCTFPlatform(srv.URL, "e2e-token", zap.NewNop())
	p.RetryBackoff = time.Millisecond
	p.MaxRetries = 3
	p.listCacheTTL = 0 // 关缓存，确保每步请求真实发出

	ctx := context.Background()

	// ── ① 拉题 ──────────────────────────────────────────
	challenges, err := p.ListChallenges(ctx)
	if err != nil {
		t.Fatalf("E2E ① 拉题失败: %v", err)
	}
	if len(challenges) != 1 {
		t.Fatalf("E2E ① 应拉到 1 道题，实际 %d", len(challenges))
	}
	if challenges[0].ID != "1001" {
		t.Fatalf("E2E ① 题号应解析为 1001，实际 %q", challenges[0].ID)
	}
	if !p.LastListOK() {
		t.Fatal("E2E ① 成功后 last_list_ok 必须为 true")
	}

	// ── ② 起靶机 ────────────────────────────────────────
	inst, err := p.CreateInstance(ctx, challenges[0].ID)
	if err != nil {
		t.Fatalf("E2E ② 起靶机失败: %v", err)
	}
	if inst == nil || inst.InstanceID != "inst-777" {
		t.Fatalf("E2E ② 实例号应为 inst-777，实际 %+v", inst)
	}
	rec.mu.Lock()
	buildBody := map[string]any{}
	if len(rec.buildBodies) > 0 {
		buildBody = rec.buildBodies[0]
	}
	rec.mu.Unlock()
	// 官方文档：body={"exerciseId":1001}（数值型）；此处校验键名拼写与取值来源
	if _, ok := buildBody["exerciseId"]; !ok {
		t.Fatalf("E2E ② 起靶机请求体缺 exerciseId 键，实际 %+v", buildBody)
	}

	// ── ③ 取访问地址 ────────────────────────────────────
	// 真源踩坑：此处必须传 exerciseId（题号），传 instanceId 会永远取空。
	acc, err := p.GetAccess(ctx, challenges[0].ID)
	if err != nil {
		t.Fatalf("E2E ③ 取靶机地址失败: %v", err)
	}
	if acc.Host != "10.20.30.40" || acc.Port != 8080 {
		t.Fatalf("E2E ③ 地址解析错误，期望 10.20.30.40:8080，实际 %s:%d", acc.Host, acc.Port)
	}
	if acc.URL != "http://10.20.30.40:8080" {
		t.Fatalf("E2E ③ URL 拼接错误，实际 %q", acc.URL)
	}
	if got := rec.countPath(defaultEndpoints["challenge_detail"] + "?exerciseId=1001"); got != 1 {
		t.Fatalf("E2E ③ 详情端点应恰好命中 1 次，实际 %d", got)
	}

	// ── ④ 提交正确 flag ─────────────────────────────────
	res, err := p.SubmitFlag(ctx, challenges[0].ID, "flag{"+rec.correctFlag+"}")
	if err != nil {
		t.Fatalf("E2E ④ 提交请求失败: %v", err)
	}
	if !res.Correct {
		t.Fatalf("E2E ④ flag 正确却判为错误，detail=%q", res.Detail)
	}
	if !res.Accepted {
		t.Fatalf("E2E ④ accepted 应为 true（业务码成功 && isCorrect），实际 false，detail=%q", res.Detail)
	}
	if res.RemainingAttempts != 4 {
		t.Fatalf("E2E ④ 剩余次数应回传 4，实际 %d", res.RemainingAttempts)
	}
	// 契约①：提交体只含 {} 内内容（手工册第 7 条）——在整链上复核，而非只测纯函数
	rec.mu.Lock()
	var sentFlag string
	if len(rec.submitBodies) > 0 {
		sentFlag, _ = rec.submitBodies[0]["flag"].(string)
	}
	rec.mu.Unlock()
	if sentFlag != rec.correctFlag {
		t.Fatalf("E2E ④ 提交体未剥离外壳：期望 %q，实际 %q", rec.correctFlag, sentFlag)
	}

	// ── ⑤ 提交错误 flag 不得被判为 accepted（防"假阳性满分"）──
	bad, err := p.SubmitFlag(ctx, challenges[0].ID, "flag{definitely_wrong}")
	if err != nil {
		t.Fatalf("E2E ⑤ 提交请求失败: %v", err)
	}
	if bad.Correct {
		t.Fatal("E2E ⑤ 错误 flag 不应判为 correct")
	}
	if bad.Accepted {
		t.Fatal("E2E ⑤ 错误 flag 不应判为 accepted（accepted=业务码成功 && isCorrect）")
	}

	// ── ⑥ 回收靶机 ──────────────────────────────────────
	if err := p.DestroyInstance(ctx, challenges[0].ID); err != nil {
		t.Fatalf("E2E ⑥ 回收靶机失败: %v", err)
	}
	rec.mu.Lock()
	rc := rec.recoverCalls
	rec.mu.Unlock()
	if rc != 1 {
		t.Fatalf("E2E ⑥ 回收端点应调用 1 次，实际 %d", rc)
	}

	// ── ⑦ 端点映射完整性：全部落在官方 /slab-match/api/v1/agent/ 族 ──
	for _, path := range rec.snapshotPaths() {
		if len(path) < len("/slab-match/api/v1/agent/") ||
			path[:len("/slab-match/api/v1/agent/")] != "/slab-match/api/v1/agent/" {
			t.Fatalf("E2E ⑦ 请求路径 %q 不在官方端点族内", path)
		}
	}
}
