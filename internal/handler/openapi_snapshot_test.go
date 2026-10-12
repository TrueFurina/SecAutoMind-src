package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestGetOpenAPISpec_Snapshot 渲染 OpenAPI spec 并校验结构完整性；
// 设 OPENAPI_SNAPSHOT 环境变量时把 JSON 落盘（用于重构前后 diff 验证）。
func TestGetOpenAPISpec_Snapshot(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &OpenAPIHandler{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil)

	h.GetOpenAPISpec(c)

	if w.Code != http.StatusOK {
		t.Fatalf("GetOpenAPISpec status = %d, want 200", w.Code)
	}
	var spec map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatalf("spec 非法 JSON: %v", err)
	}
	if spec["openapi"] != "3.0.0" {
		t.Errorf("openapi = %v, want 3.0.0", spec["openapi"])
	}
	paths, _ := spec["paths"].(map[string]interface{})
	if len(paths) < 30 {
		t.Errorf("paths 数量异常: %d", len(paths))
	}
	components, _ := spec["components"].(map[string]interface{})
	schemas, _ := components["schemas"].(map[string]interface{})
	if len(schemas) < 5 {
		t.Errorf("schemas 数量异常: %d", len(schemas))
	}
	if len(spec["security"].([]interface{})) == 0 {
		t.Error("security 不应为空")
	}

	if out := os.Getenv("OPENAPI_SNAPSHOT"); out != "" {
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			t.Fatalf("创建快照目录失败: %v", err)
		}
		if err := os.WriteFile(out, w.Body.Bytes(), 0o644); err != nil {
			t.Fatalf("写快照失败: %v", err)
		}
		t.Logf("快照已写入 %s (%d bytes)", out, len(w.Body.Bytes()))
	}
}
