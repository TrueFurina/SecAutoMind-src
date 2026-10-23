package security

import (
	"testing"

	"secautomind-ai/internal/config"
)

// paramProvided 的判定表驱动测试：bool 仅 true 算提供，string 须非空白。
func TestParamProvided(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want bool
	}{
		{"nil 不算", nil, false},
		{"bool true 算", true, true},
		{"bool false 不算", false, false},
		{"空字符串不算", "", false},
		{"纯空白字符串不算", "   ", false},
		{"非空字符串算", "eth0", true},
		{"int 非 nil 算", 300, true},
		{"float 非 nil 算", 1.5, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := paramProvided(c.in); got != c.want {
				t.Fatalf("paramProvided(%#v)=%v, want %v", c.in, got, c.want)
			}
		})
	}
}

// validateRequiresAnyOf：至少一个被实质提供即通过，否则报错（fail-closed，绝不执行命令）。
func TestValidateRequiresAnyOf(t *testing.T) {
	e := &Executor{}

	t.Run("未声明原语则不约束", func(t *testing.T) {
		cfg := &config.ToolConfig{Name: "checkov"}
		if err := e.validateRequiresAnyOf("checkov", cfg, nil); err != nil {
			t.Fatalf("未声明 requires_any_of 不应报错，got %v", err)
		}
	})

	t.Run("arp-scan 给 target 通过", func(t *testing.T) {
		cfg := &config.ToolConfig{Name: "arp-scan", RequiresAnyOf: []string{"target", "local_network"}}
		args := map[string]interface{}{"target": "192.168.1.0/24"}
		if err := e.validateRequiresAnyOf("arp-scan", cfg, args); err != nil {
			t.Fatalf("target 已提供不应报错，got %v", err)
		}
	})

	t.Run("arp-scan 给 local_network=true 通过", func(t *testing.T) {
		cfg := &config.ToolConfig{Name: "arp-scan", RequiresAnyOf: []string{"target", "local_network"}}
		args := map[string]interface{}{"local_network": true}
		if err := e.validateRequiresAnyOf("arp-scan", cfg, args); err != nil {
			t.Fatalf("local_network=true 已提供不应报错，got %v", err)
		}
	})

	t.Run("arp-scan 空参数必须报错", func(t *testing.T) {
		cfg := &config.ToolConfig{Name: "arp-scan", RequiresAnyOf: []string{"target", "local_network"}}
		if err := e.validateRequiresAnyOf("arp-scan", cfg, map[string]interface{}{}); err == nil {
			t.Fatal("空参数应报错（fail-closed），got nil")
		}
	})

	t.Run("local_network=false 不视为提供", func(t *testing.T) {
		cfg := &config.ToolConfig{Name: "arp-scan", RequiresAnyOf: []string{"target", "local_network"}}
		args := map[string]interface{}{"local_network": false}
		if err := e.validateRequiresAnyOf("arp-scan", cfg, args); err == nil {
			t.Fatal("local_network=false 等于未开启，应报错")
		}
	})

	t.Run("target 为空字符串不视为提供", func(t *testing.T) {
		cfg := &config.ToolConfig{Name: "kube-hunter", RequiresAnyOf: []string{"target", "cidr", "interface"}}
		args := map[string]interface{}{"target": "  "}
		if err := e.validateRequiresAnyOf("kube-hunter", cfg, args); err == nil {
			t.Fatal("target 为空白应视为未提供，应报错")
		}
	})

	t.Run("kube-hunter 给 cidr 通过", func(t *testing.T) {
		cfg := &config.ToolConfig{Name: "kube-hunter", RequiresAnyOf: []string{"target", "cidr", "interface"}}
		args := map[string]interface{}{"cidr": "10.0.0.0/8"}
		if err := e.validateRequiresAnyOf("kube-hunter", cfg, args); err != nil {
			t.Fatalf("cidr 已提供不应报错，got %v", err)
		}
	})
}
