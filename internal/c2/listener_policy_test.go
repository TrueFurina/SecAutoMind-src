package c2

import (
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"secautomind-ai/internal/database"

	"go.uber.org/zap"
)

// ───────────────────────── 回环判定 ─────────────────────────

func TestIsLoopbackBindHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"", true},              // 默认回环（CreateListener 兜底 127.0.0.1）
		{"127.0.0.1", true},     // 标准回环
		{"127.0.0.2", true},     // 127.0.0.0/8 整段回环
		{"127.255.255.254", true},
		{"localhost", true}, // 主机名
		{"LOCALHOST", true}, // 大小写不敏感
		{"::1", true},       // IPv6 回环
		{"[::1]", true},     // 带方括号
		{"0:0:0:0:0:0:0:1", true},

		{"0.0.0.0", false},        // 全网卡（本次事故根因）
		{"::", false},             // IPv6 全网卡
		{"192.168.1.10", false},   // 内网地址 ≠ 回环
		{"120.48.36.201", false},  // 公网地址
		{"10.0.0.5", false},       // 内网
		{"172.16.0.1", false},     // 内网
		{"c2.example.com", false}, // 域名：无法证明回环，从严
		{" 127.0.0.1 ", true},     // 前后空白
	}
	for _, c := range cases {
		if got := IsLoopbackBindHost(c.host); got != c.want {
			t.Errorf("IsLoopbackBindHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// ───────────────────────── 策略校验（纯函数） ─────────────────────────

func TestValidateListenerPolicy(t *testing.T) {
	tcp := string(ListenerTypeTCPReverse)
	httpB := string(ListenerTypeHTTPBeacon)

	cases := []struct {
		name     string
		ltype    string
		bindHost string
		cfg      *ListenerConfig
		wantErr  bool
	}{
		{"tcp_reverse + legacy + 0.0.0.0 → 拒绝（事故组合）", tcp, "0.0.0.0", &ListenerConfig{AllowLegacyShell: true}, true},
		{"tcp_reverse + legacy + :: → 拒绝", tcp, "::", &ListenerConfig{AllowLegacyShell: true}, true},
		{"tcp_reverse + legacy + 公网IP → 拒绝", tcp, "120.48.36.201", &ListenerConfig{AllowLegacyShell: true}, true},
		{"tcp_reverse + legacy + 内网IP → 拒绝（内网≠回环）", tcp, "192.168.1.10", &ListenerConfig{AllowLegacyShell: true}, true},

		{"tcp_reverse + legacy + 127.0.0.1 → 放行", tcp, "127.0.0.1", &ListenerConfig{AllowLegacyShell: true}, false},
		{"tcp_reverse + legacy + ::1 → 放行", tcp, "::1", &ListenerConfig{AllowLegacyShell: true}, false},
		{"tcp_reverse + legacy + 空 → 放行（默认回环）", tcp, "", &ListenerConfig{AllowLegacyShell: true}, false},

		{"tcp_reverse + 非legacy + 0.0.0.0 → 放行（加密Beacon本就应能公网）", tcp, "0.0.0.0", &ListenerConfig{AllowLegacyShell: false}, false},
		{"tcp_reverse + cfg nil → 放行", tcp, "0.0.0.0", nil, false},
		{"http_beacon + legacy + 0.0.0.0 → 放行（开关对其无意义）", httpB, "0.0.0.0", &ListenerConfig{AllowLegacyShell: true}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateListenerPolicy(c.ltype, c.bindHost, c.cfg)
			if c.wantErr && !errors.Is(err, ErrLegacyShellPublicBind) {
				t.Errorf("期望 ErrLegacyShellPublicBind，got %v", err)
			}
			if !c.wantErr && err != nil {
				t.Errorf("期望放行，got %v", err)
			}
		})
	}
}

// ───────────────────────── 接入点集成校验 ─────────────────────────

func newPolicyTestManager(t *testing.T) *Manager {
	t.Helper()
	tmp := t.TempDir()
	db, err := database.NewDB(filepath.Join(tmp, "c2.sqlite"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mgr := NewManager(db, zap.NewNop(), tmp)
	mgr.Registry().Register(string(ListenerTypeTCPReverse), NewTCPReverseListener)
	return mgr
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

// TestCreateListener_RejectsPublicLegacyShell —— 创建入口拒绝公网 legacy shell。
func TestCreateListener_RejectsPublicLegacyShell(t *testing.T) {
	mgr := newPolicyTestManager(t)
	_, err := mgr.CreateListener(CreateListenerInput{
		Name:     "Port Scanner 2",
		Type:     string(ListenerTypeTCPReverse),
		BindHost: "0.0.0.0",
		BindPort: freePort(t),
		Config:   &ListenerConfig{AllowLegacyShell: true},
	})
	if !errors.Is(err, ErrLegacyShellPublicBind) {
		t.Fatalf("创建入口未拦截公网 legacy shell，got %v", err)
	}
	// 回环地址应放行
	if _, err := mgr.CreateListener(CreateListenerInput{
		Name:     "loopback legacy",
		Type:     string(ListenerTypeTCPReverse),
		BindHost: "127.0.0.1",
		BindPort: freePort(t),
		Config:   &ListenerConfig{AllowLegacyShell: true},
	}); err != nil {
		t.Fatalf("回环 legacy shell 应放行，got %v", err)
	}
}

// TestStartListener_RejectsLegacyRecordOnPublicBind —— 启动入口拦截"数据库里已存在的违规历史记录"。
// 这是根治的关键：躲过 create 校验的存量记录（如线上 0.0.0.0:5555）在进程重启时也不会被拉起。
func TestStartListener_RejectsLegacyRecordOnPublicBind(t *testing.T) {
	mgr := newPolicyTestManager(t)
	db := mgr.DB()

	// 绕过 Manager 直插数据库，模拟"存量违规记录"
	rec := &database.C2Listener{
		ID:         "l_legacypublic0001",
		Name:       "存量违规监听器",
		Type:       string(ListenerTypeTCPReverse),
		BindHost:   "0.0.0.0",
		BindPort:   freePort(t),
		Status:     "stopped",
		ConfigJSON: `{"allow_legacy_shell":true}`,
		CreatedAt:  time.Now(),
	}
	if err := db.CreateC2Listener(rec); err != nil {
		t.Fatal(err)
	}

	if _, err := mgr.StartListener(rec.ID); !errors.Is(err, ErrLegacyShellPublicBind) {
		t.Fatalf("启动入口未拦截存量违规记录，got %v", err)
	}
	// 落库状态应为 error，便于运维在 UI 上看见
	got, err := db.GetC2Listener(rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "error" {
		t.Errorf("拒绝后状态应为 error，got %q", got.Status)
	}
	if got.LastError == "" {
		t.Error("拒绝后应写入 LastError 便于排查")
	}
}

// TestRestoreRunningListeners_SkipsPublicLegacyShell —— 重启恢复路径同样不拉起违规监听器。
func TestRestoreRunningListeners_SkipsPublicLegacyShell(t *testing.T) {
	mgr := newPolicyTestManager(t)
	db := mgr.DB()

	bad := &database.C2Listener{
		ID:         "l_badrestore00001",
		Name:       "违规且标记 running",
		Type:       string(ListenerTypeTCPReverse),
		BindHost:   "0.0.0.0",
		BindPort:   freePort(t),
		Status:     "running", // 进程重启时 RestoreRunningListeners 会尝试拉起
		ConfigJSON: `{"allow_legacy_shell":true}`,
		CreatedAt:  time.Now(),
	}
	if err := db.CreateC2Listener(bad); err != nil {
		t.Fatal(err)
	}

	mgr.RestoreRunningListeners()

	if mgr.IsListenerRunning(bad.ID) {
		t.Fatal("安全违规监听器在重启恢复时被拉起——公网 RCE 面暴露")
	}
}

// 变异自检：把策略函数改成"永远放行"后，上面三个测试必须 FAIL。
func TestPolicyMutationSelfCheck(t *testing.T) {
	// 保证被拦截的组合确实是"会被拒绝"的，而非测试写错了分支
	if err := ValidateListenerPolicy(string(ListenerTypeTCPReverse), "0.0.0.0",
		&ListenerConfig{AllowLegacyShell: true}); err == nil {
		t.Fatal("变异自检失败：事故组合竟被放行，策略未生效")
	}
	// 且必须不影响正常用法（加密 Beacon 公网监听）
	if err := ValidateListenerPolicy(string(ListenerTypeTCPReverse), "0.0.0.0",
		&ListenerConfig{AllowLegacyShell: false}); err != nil {
		t.Fatalf("加密 Beacon 公网监听被误伤：%v", err)
	}
}
