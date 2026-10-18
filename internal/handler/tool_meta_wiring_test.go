package handler

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"secautomind-ai/internal/config"
)

// TestGetToolsMetaWiring 保证工具元数据（version/source/upstream/license/trust/evidence）
// 真的从 tools/*.yaml 经 GetTools 走到前端 —— 防止"struct 加了字段但忘记在
// 某个返回入口填充"的回归（本仓库第八条：定义齐全 ≠ 接线）。
//
// 自包含：临时目录里造最小 tools 配置，不依赖开发机上的 config.yaml（CI 容器内没有它）。
func TestGetToolsMetaWiring(t *testing.T) {
	tmp := t.TempDir()
	toolsDir := filepath.Join(tmp, "tools")
	if err := os.MkdirAll(toolsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	toolYAML := "name: \"demo-tool\"\n" +
		"command: \"demo\"\n" +
		"enabled: true\n" +
		"version: \"9.9.9\"\n" +
		"source: \"self\"\n" +
		"upstream: \"https://example.invalid/demo\"\n" +
		"license: \"MIT\"\n" +
		"trust: \"verified\"\n" +
		"evidence: \"docs/demo-golden.json\"\n" +
		"short_description: \"演示工具\"\n"
	if err := os.WriteFile(filepath.Join(toolsDir, "demo.yaml"), []byte(toolYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	tools, err := config.LoadToolsFromDir(toolsDir)
	if err != nil {
		t.Fatalf("LoadToolsFromDir: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("期望加载 1 个工具，实际 %d", len(tools))
	}
	if tools[0].Source != "self" || tools[0].Trust != "verified" {
		t.Fatalf("元数据未被 ToolConfig 解析: %+v", tools[0])
	}

	cfg := &config.Config{}
	cfg.Security.Tools = tools
	h := &ConfigHandler{
		configPath: filepath.Join(tmp, "config.yaml"),
		config:     cfg,
		logger:     zap.NewNop(),
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/config/tools?page=1&page_size=20&include_external=0", nil)

	h.GetTools(c)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		`"source":"self"`,
		`"trust":"verified"`,
		`"version":"9.9.9"`,
		`"license":"MIT"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("GetTools 响应缺少 %s —— 前端拿不到元数据", want)
		}
	}
}
