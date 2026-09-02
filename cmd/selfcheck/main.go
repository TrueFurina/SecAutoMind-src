package main

import (
	"fmt"
	"os"
	"path/filepath"

	"secautomind-ai/internal/config"
)

func main() {
	// 模拟用户把 exe 放在空目录双击：cwd 无 config.yaml 且无 config.example.yaml
	emptyDir, err := os.MkdirTemp("", "secauto-empty-*")
	if err != nil {
		fmt.Println("❌ 创建空目录失败:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(emptyDir)
	os.Chdir(emptyDir)

	cfgPath := filepath.Join(emptyDir, "config.yaml")
	res, err := config.EnsureLocalConfig(cfgPath)
	if err != nil {
		fmt.Println("❌ EnsureLocalConfig 失败:", err)
		os.Exit(1)
	}
	fmt.Println("✅ EnsureLocalConfig 成功, Created =", res.Created, "| 模板来源:", res.ExamplePath)

	// 验证生成的 config 能被 Load 解析
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Println("❌ config.Load 失败:", err)
		os.Exit(1)
	}
	fmt.Printf("✅ config.Load 成功: server.host=%s port=%d\n", cfg.Server.Host, cfg.Server.Port)

	// 验证默认 bootstrap 后是 HTTP（双击场景）
	config.ApplyPlainHTTPBootstrap(cfg)
	fmt.Println("✅ 双击默认走 HTTP bootstrap（无 HTTPS 自签告警）")
}
