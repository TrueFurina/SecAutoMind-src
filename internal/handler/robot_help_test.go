package handler

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secautomind-ai/internal/config"
	"secautomind-ai/internal/database"
	"secautomind-ai/internal/security"

	"go.uber.org/zap"
)

// newHelpTestHandler 构造一个权限齐全的 handler，使 cmdHelp 渲染出全部门控章节
// （对话/角色/模式/漏洞提醒/项目），从而保证加粗平衡性测试覆盖到所有 b.WriteString 字面量。
func newHelpTestHandler(t *testing.T) *RobotHandler {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "help.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.BootstrapRBAC("hash", security.PermissionCatalog); err != nil {
		t.Fatal(err)
	}
	// 管理员角色拥有全部权限（含 config:read / project:read|write）。
	user, err := db.CreateRBACUser("help-admin", "Help Admin", "hash", true, []string{database.RBACSystemRoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateRobotBindingCode(user.ID, "help-code", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ConsumeRobotBindingCode("wechat", "t:wechat|u:help", "help-code"); err != nil {
		t.Fatal(err)
	}
	return NewRobotHandler(&config.Config{Project: config.ProjectConfig{Enabled: true}}, db, nil, zap.NewNop())
}

// TestCmdHelp_BoldIsBalanced 锁死帮助文本的加粗必须成对：
// 任意一个未闭合的 ** 都会让 IM 客户端把其后所有内容整段加粗
// （用户实证缺陷——帮助前半段无加粗、后半段整段加粗即此因）。
// 每个 b.WriteString 内的 ** 都成对，拼接后总数必为偶数。
func TestCmdHelp_BoldIsBalanced(t *testing.T) {
	out := newHelpTestHandler(t).cmdHelp("wechat", "t:wechat|u:help")
	if n := strings.Count(out, "**"); n%2 != 0 {
		t.Fatalf("帮助文本存在未闭合的 **（加粗标记数 %d 为奇数），IM 端会整段误加粗:\n%s", n, out)
	}
}

// TestCmdHelp_HasExpectedSections 锁死关键章节与命令关键词的加粗存在，
// 防止回归把成对加粗整段删掉或写错（如漏写闭合 **）。
func TestCmdHelp_HasExpectedSections(t *testing.T) {
	out := newHelpTestHandler(t).cmdHelp("wechat", "t:wechat|u:help")
	for _, want := range []string{
		"**【SecAutoMind 机器人命令】**",
		"**【通用 General】**",
		"**帮助 / help**",
		"**诊断 / doctor**",
		"**【项目 Project】**",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("帮助缺少预期加粗章节/命令 %q:\n%s", want, out)
		}
	}
}
