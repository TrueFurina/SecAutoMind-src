package handler

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"secautomind-ai/internal/collab"
	"secautomind-ai/internal/database"
	"secautomind-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// collabTestRouter 装配一个只挂协同路由的 gin 引擎，并按 session 注入身份。
// 这里刻意不走完整 RBAC 中间件：本层要验的是「路由接线 + 错误映射」，
// 权限判定本身由 security.RequirePermission 的既有测试覆盖。
func collabTestRouter(t *testing.T, session security.Session) (*gin.Engine, *database.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := database.NewDB(filepath.Join(t.TempDir(), "collab_handler.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	svc := collab.New(collab.Options{DB: db, Logger: zap.NewNop(), WallClock: time.Minute})
	h := NewCollabHandler(svc, zap.NewNop())

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, session)
		c.Next()
	})
	r.GET("/collab/overview", h.Overview)
	r.GET("/collab/seats", h.ListSeats)
	r.POST("/collab/seats", h.CreateSeat)
	r.GET("/collab/seats/:id", h.GetSeat)
	r.PUT("/collab/seats/:id", h.UpdateSeat)
	r.DELETE("/collab/seats/:id", h.DeleteSeat)
	r.GET("/collab/tasks", h.ListTasks)
	r.POST("/collab/tasks", h.EnqueueTask)
	r.GET("/collab/tasks/:id", h.GetTask)
	r.POST("/collab/tasks/:id/claim", h.ClaimTask)
	r.POST("/collab/tasks/:id/complete", h.CompleteTask)
	r.POST("/collab/tasks/:id/abandon", h.AbandonTask)
	r.POST("/collab/tasks/:id/renew", h.RenewTask)
	r.POST("/collab/reaper/run", h.RunReaper)
	return r, db
}

func adminSession() security.Session {
	return security.Session{
		UserID: "u-admin", Username: "admin",
		Scope: database.RBACScopeAll,
	}
}

func doJSON(t *testing.T, r *gin.Engine, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func decodeMap(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	out := map[string]interface{}{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return out
}

func TestCollabRoutesHappyPath(t *testing.T) {
	r, _ := collabTestRouter(t, adminSession())

	// 建席位
	w := doJSON(t, r, http.MethodPost, "/collab/seats", map[string]interface{}{
		"kind": "agent", "display_name": "Agent-1",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("创建席位: code=%d body=%s", w.Code, w.Body.String())
	}
	seatID := decodeMap(t, w)["seat"].(map[string]interface{})["id"].(string)

	// 入池
	w = doJSON(t, r, http.MethodPost, "/collab/tasks", map[string]interface{}{
		"title": "web-1", "message": "find the flag",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("入池: code=%d body=%s", w.Code, w.Body.String())
	}
	taskID := decodeMap(t, w)["task"].(map[string]interface{})["id"].(string)

	// 领取
	w = doJSON(t, r, http.MethodPost, "/collab/tasks/"+taskID+"/claim", map[string]interface{}{"seat_id": seatID})
	if w.Code != http.StatusOK {
		t.Fatalf("领取: code=%d body=%s", w.Code, w.Body.String())
	}
	claim := decodeMap(t, w)
	if claim["claimed"] != true {
		t.Fatalf("首次领取应成功: %v", claim)
	}
	token, _ := claim["claim_token"].(string)
	if token == "" {
		t.Fatal("领取应返回 claim_token（回写凭据）")
	}

	// 再次领取：不是错误，是输掉竞争 → 200 + claimed=false
	w = doJSON(t, r, http.MethodPost, "/collab/tasks/"+taskID+"/claim", map[string]interface{}{"seat_id": seatID})
	if w.Code != http.StatusOK || decodeMap(t, w)["claimed"] != false {
		t.Fatalf("二次领取应为 200/claimed=false，实得 code=%d body=%s", w.Code, w.Body.String())
	}

	// 完成
	w = doJSON(t, r, http.MethodPost, "/collab/tasks/"+taskID+"/complete",
		map[string]interface{}{"seat_id": seatID, "claim_token": token, "result": "flag{ok}"})
	if w.Code != http.StatusOK {
		t.Fatalf("完成: code=%d body=%s", w.Code, w.Body.String())
	}

	// 总览
	w = doJSON(t, r, http.MethodGet, "/collab/overview", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("总览: code=%d body=%s", w.Code, w.Body.String())
	}
	ov := decodeMap(t, w)
	if ov["total"].(float64) != 1 {
		t.Fatalf("总览任务数应为 1: %v", ov["total"])
	}
	totals := ov["totals"].(map[string]interface{})
	if totals[database.CollabTaskStatusDone].(float64) != 1 {
		t.Fatalf("总览 done 数应为 1: %v", totals)
	}
}

func TestCollabRoutesErrorMapping(t *testing.T) {
	r, _ := collabTestRouter(t, adminSession())

	// 400：human 席缺 username
	w := doJSON(t, r, http.MethodPost, "/collab/seats", map[string]interface{}{
		"kind": "human", "display_name": "无主",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("非法入参应 400，实得 %d body=%s", w.Code, w.Body.String())
	}

	// 404：任务不存在
	w = doJSON(t, r, http.MethodGet, "/collab/tasks/ctask_missing", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("未知任务应 404，实得 %d body=%s", w.Code, w.Body.String())
	}

	// 404：席位不存在
	w = doJSON(t, r, http.MethodGet, "/collab/seats/seat_missing", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("未知席位应 404，实得 %d body=%s", w.Code, w.Body.String())
	}

	// 409：token 失配
	w = doJSON(t, r, http.MethodPost, "/collab/seats", map[string]interface{}{
		"kind": "agent", "display_name": "Agent-1",
	})
	seatID := decodeMap(t, w)["seat"].(map[string]interface{})["id"].(string)
	w = doJSON(t, r, http.MethodPost, "/collab/tasks", map[string]interface{}{"title": "t", "message": "m"})
	taskID := decodeMap(t, w)["task"].(map[string]interface{})["id"].(string)
	doJSON(t, r, http.MethodPost, "/collab/tasks/"+taskID+"/claim", map[string]interface{}{"seat_id": seatID})

	w = doJSON(t, r, http.MethodPost, "/collab/tasks/"+taskID+"/complete",
		map[string]interface{}{"seat_id": seatID, "claim_token": "claim_bogus", "result": "x"})
	if w.Code != http.StatusConflict {
		t.Fatalf("token 失配应 409，实得 %d body=%s", w.Code, w.Body.String())
	}
}

func TestCollabRoutesSeatForbidden(t *testing.T) {
	// bob 是普通队员（非全局 scope），试图冒用 alice 的席位
	r, db := collabTestRouter(t, security.Session{
		UserID: "u-bob", Username: "bob", Scope: database.RBACScopeOwn,
	})

	now := time.Now()
	for _, s := range []*database.CollabSeatRow{
		{ID: "seat_alice", Kind: database.CollabSeatKindHuman, DisplayName: "张三",
			Username: sql.NullString{String: "alice", Valid: true},
			Status:   database.CollabSeatStatusIdle, CreatedAt: now, UpdatedAt: now},
		{ID: "seat_bob", Kind: database.CollabSeatKindHuman, DisplayName: "李四",
			Username: sql.NullString{String: "bob", Valid: true},
			Status:   database.CollabSeatStatusIdle, CreatedAt: now, UpdatedAt: now},
	} {
		if err := db.CreateCollabSeat(s); err != nil {
			t.Fatalf("CreateCollabSeat: %v", err)
		}
	}
	if err := db.EnqueueCollabTask(&database.CollabTaskRow{
		ID: "ctask_1", Title: "t", Message: "m", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("EnqueueCollabTask: %v", err)
	}

	// 403：冒用 alice 的席位
	w := doJSON(t, r, http.MethodPost, "/collab/tasks/ctask_1/claim", map[string]interface{}{"seat_id": "seat_alice"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("冒用他人席位应 403，实得 %d body=%s", w.Code, w.Body.String())
	}
	// 放行：用本人席位
	w = doJSON(t, r, http.MethodPost, "/collab/tasks/ctask_1/claim", map[string]interface{}{"seat_id": "seat_bob"})
	if w.Code != http.StatusOK || decodeMap(t, w)["claimed"] != true {
		t.Fatalf("本人席位应可领取，实得 %d body=%s", w.Code, w.Body.String())
	}
	// 读放行：能看到任务列表与总览
	if w = doJSON(t, r, http.MethodGet, "/collab/tasks", nil); w.Code != http.StatusOK {
		t.Fatalf("读任务应放行，实得 %d", w.Code)
	}
	if w = doJSON(t, r, http.MethodGet, "/collab/overview", nil); w.Code != http.StatusOK {
		t.Fatalf("读总览应放行，实得 %d", w.Code)
	}
}

func TestCollabRoutesServiceDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewCollabHandler(nil, zap.NewNop())
	r := gin.New()
	r.GET("/collab/overview", h.Overview)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/collab/overview", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("服务未启用应 503，实得 %d", w.Code)
	}
}
