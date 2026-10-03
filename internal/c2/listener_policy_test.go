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

// ───────────────────────── 载荷加密真值表 ─────────────────────────

// TestIsEncryptedListener —— 矩阵的"加密列"必须由实现事实决定，而非猜测。
// 证据：listener_http.go 中 https_beacon 构造器 useTLS=true（TLS 配置失败即启动失败，
// 不会回落明文）；tcp_beacon_server.go 用 CSB1 魔数 + AES-GCM；listener_websocket.go
// 全文无 TLS（ws:// 明文）；http_beacon 为明文 HTTP。
func TestIsEncryptedListener(t *testing.T) {
	cases := []struct {
		name  string
		ltype string
		cfg   *ListenerConfig
		want  bool
	}{
		{"https_beacon → TLS 加密", string(ListenerTypeHTTPSBeacon), &ListenerConfig{}, true},
		{"https_beacon + nil cfg → 仍加密", string(ListenerTypeHTTPSBeacon), nil, true},
		{"tcp_reverse 非 legacy → CSB1 加密", string(ListenerTypeTCPReverse), &ListenerConfig{}, true},
		{"tcp_reverse + cfg nil → 加密（默认不开 legacy）", string(ListenerTypeTCPReverse), nil, true},
		{"tcp_reverse + legacy → 明文", string(ListenerTypeTCPReverse), &ListenerConfig{AllowLegacyShell: true}, false},
		{"http_beacon → 明文", string(ListenerTypeHTTPBeacon), &ListenerConfig{}, false},
		{"http_beacon + 误开 legacy 开关 → 仍明文", string(ListenerTypeHTTPBeacon), &ListenerConfig{AllowLegacyShell: true}, false},
		{"websocket → 明文（实现层无 TLS）", string(ListenerTypeWebSocket), &ListenerConfig{}, false},
		{"未知类型 → fail-closed 按明文", "smtp_evil", &ListenerConfig{}, false},
		{"大小写与空白容错", " HTTPS_BEACON ", &ListenerConfig{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsEncryptedListener(c.ltype, c.cfg); got != c.want {
				t.Errorf("IsEncryptedListener(%q) = %v, want %v", c.ltype, got, c.want)
			}
		})
	}
}

// ───────────────────────── 策略校验（纯函数·完整矩阵） ─────────────────────────

func TestValidateListenerPolicy(t *testing.T) {
	tcp := string(ListenerTypeTCPReverse)
	httpB := string(ListenerTypeHTTPBeacon)
	httpsB := string(ListenerTypeHTTPSBeacon)
	ws := string(ListenerTypeWebSocket)

	cases := []struct {
		name     string
		ltype    string
		bindHost string
		cfg      *ListenerConfig
		wantErr  error // nil = 放行
	}{
		// ── 回环绑定一律放行 ──
		{"http_beacon + 127.0.0.1 → 放行", httpB, "127.0.0.1", nil, nil},
		{"websocket + ::1 → 放行", ws, "::1", nil, nil},
		{"tcp_reverse + legacy + 空 → 放行（默认回环）", tcp, "", &ListenerConfig{AllowLegacyShell: true}, nil},
		{"未知类型 + localhost → 放行（回环不设限）", "smtp_evil", "localhost", nil, nil},

		// ── 加密载荷允许非回环（反向自检：正常用法不得被误伤） ──
		{"https_beacon + 0.0.0.0 → 放行（TLS）", httpsB, "0.0.0.0", nil, nil},
		{"https_beacon + 公网IP → 放行（TLS）", httpsB, "120.48.36.201", &ListenerConfig{TLSAutoSelfSign: true}, nil},
		{"https_beacon + :: → 放行（TLS）", httpsB, "::", &ListenerConfig{}, nil},
		{"tcp_reverse 非 legacy + 0.0.0.0 → 放行（CSB1 加密）", tcp, "0.0.0.0", &ListenerConfig{AllowLegacyShell: false}, nil},
		{"tcp_reverse + cfg nil + 0.0.0.0 → 放行", tcp, "0.0.0.0", nil, nil},

		// ── 明文载荷仅回环（10-04 漏网组合：公网 http_beacon） ──
		{"http_beacon + 0.0.0.0 → 拒绝（10-04 线上漏网组合）", httpB, "0.0.0.0", nil, ErrPlaintextPublicBind},
		{"http_beacon + :: → 拒绝", httpB, "::", &ListenerConfig{}, ErrPlaintextPublicBind},
		{"http_beacon + 公网IP → 拒绝", httpB, "120.48.36.201", nil, ErrPlaintextPublicBind},
		{"http_beacon + 内网IP → 拒绝（内网≠回环）", httpB, "10.0.0.5", nil, ErrPlaintextPublicBind},
		{"http_beacon + 域名 → 拒绝（无法证明回环）", httpB, "c2.example.com", nil, ErrPlaintextPublicBind},
		{"websocket + 0.0.0.0 → 拒绝", ws, "0.0.0.0", nil, ErrPlaintextPublicBind},
		{"websocket + 公网IP → 拒绝", ws, "120.48.36.201", &ListenerConfig{}, ErrPlaintextPublicBind},
		{"未知类型 + 0.0.0.0 → 拒绝（fail-closed）", "smtp_evil", "0.0.0.0", nil, ErrPlaintextPublicBind},

		// ── legacy shell 专用错误码（比通用明文错误更精确） ──
		{"tcp_reverse + legacy + 0.0.0.0 → 专用错误", tcp, "0.0.0.0", &ListenerConfig{AllowLegacyShell: true}, ErrLegacyShellPublicBind},
		{"tcp_reverse + legacy + :: → 专用错误", tcp, "::", &ListenerConfig{AllowLegacyShell: true}, ErrLegacyShellPublicBind},
		{"tcp_reverse + legacy + 公网IP → 专用错误", tcp, "120.48.36.201", &ListenerConfig{AllowLegacyShell: true}, ErrLegacyShellPublicBind},
		{"tcp_reverse + legacy + 内网IP → 专用错误", tcp, "192.168.1.10", &ListenerConfig{AllowLegacyShell: true}, ErrLegacyShellPublicBind},
		// 修正旧断言：原用例把该组合写成"放行（开关对其无意义）"，锁定的正是 10-04 漏网的
		// bug；legacy 开关对 http_beacon 确实无意义，但 http_beacon 本身是明文，仍须拒绝。
		{"http_beacon + 误开 legacy + 0.0.0.0 → 通用明文错误", httpB, "0.0.0.0", &ListenerConfig{AllowLegacyShell: true}, ErrPlaintextPublicBind},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateListenerPolicy(c.ltype, c.bindHost, c.cfg)
			if c.wantErr == nil {
				if err != nil {
					t.Fatalf("期望放行，got %v", err)
				}
				return
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("期望 %v，got %v", c.wantErr, err)
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
	mgr.Registry().Register(string(ListenerTypeHTTPBeacon), NewHTTPBeaconListener)
	mgr.Registry().Register(string(ListenerTypeWebSocket), NewWebSocketListener)
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

// TestCreateListener_RejectsPublicPlaintextBeacon —— 创建入口拒绝公网明文 http_beacon/websocket，
// 且拒绝时**不得落库**（避免"配置非法却留下半成品记录"）。
func TestCreateListener_RejectsPublicPlaintextBeacon(t *testing.T) {
	for _, typ := range []string{string(ListenerTypeHTTPBeacon), string(ListenerTypeWebSocket)} {
		t.Run(typ, func(t *testing.T) {
			mgr := newPolicyTestManager(t)
			_, err := mgr.CreateListener(CreateListenerInput{
				Name:     "公网明文监听器",
				Type:     typ,
				BindHost: "0.0.0.0",
				BindPort: freePort(t),
			})
			if !errors.Is(err, ErrPlaintextPublicBind) {
				t.Fatalf("创建入口未拦截公网明文 %s，got %v", typ, err)
			}
			recs, lerr := mgr.DB().ListC2Listeners()
			if lerr != nil {
				t.Fatal(lerr)
			}
			if len(recs) != 0 {
				t.Fatalf("被拒绝的监听器不应落库，got %d 条", len(recs))
			}
			// 回环地址应放行（同等配置仅换绑定地址）
			if _, err := mgr.CreateListener(CreateListenerInput{
				Name:     "回环明文监听器",
				Type:     typ,
				BindHost: "127.0.0.1",
				BindPort: freePort(t),
			}); err != nil {
				t.Fatalf("回环 %s 应放行，got %v", typ, err)
			}
		})
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

// TestStartListener_RejectsPlaintextRecordOnPublicBind —— 同一入口必须覆盖矩阵的另一格：
// 存量公网 http_beacon（10-04 线上实际存在的形态）在启动/重启恢复时不得被拉起。
func TestStartListener_RejectsPlaintextRecordOnPublicBind(t *testing.T) {
	mgr := newPolicyTestManager(t)
	db := mgr.DB()

	rec := &database.C2Listener{
		ID:         "l_plainpublic0001",
		Name:       "渗透测试监听器",
		Type:       string(ListenerTypeHTTPBeacon),
		BindHost:   "0.0.0.0",
		BindPort:   freePort(t),
		Status:     "stopped",
		ConfigJSON: `{}`,
		CreatedAt:  time.Now(),
	}
	if err := db.CreateC2Listener(rec); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.StartListener(rec.ID); !errors.Is(err, ErrPlaintextPublicBind) {
		t.Fatalf("启动入口未拦截存量公网明文 http_beacon，got %v", err)
	}
	got, err := db.GetC2Listener(rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "error" || got.LastError == "" {
		t.Errorf("拒绝后应为 error 且带 LastError，got status=%q lastErr=%q", got.Status, got.LastError)
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

// TestRestoreRunningListeners_SkipsPublicPlaintextBeacon —— 矩阵另一格的重启恢复覆盖。
func TestRestoreRunningListeners_SkipsPublicPlaintextBeacon(t *testing.T) {
	mgr := newPolicyTestManager(t)
	db := mgr.DB()

	bad := &database.C2Listener{
		ID:         "l_plainrestore001",
		Name:       "测试端口冲突",
		Type:       string(ListenerTypeHTTPBeacon),
		BindHost:   "0.0.0.0",
		BindPort:   freePort(t),
		Status:     "running",
		ConfigJSON: `{}`,
		CreatedAt:  time.Now(),
	}
	if err := db.CreateC2Listener(bad); err != nil {
		t.Fatal(err)
	}

	mgr.RestoreRunningListeners()

	if mgr.IsListenerRunning(bad.ID) {
		t.Fatal("公网明文 http_beacon 在重启恢复时被拉起——公网暴露面未被策略锁死")
	}
	got, err := db.GetC2Listener(bad.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "error" {
		t.Errorf("恢复路径拒绝后状态应为 error，got %q", got.Status)
	}
}

// 变异自检：把策略改成"永远放行"后，上面三个测试必须 FAIL。
func TestPolicyMutationSelfCheck(t *testing.T) {
	// 保证被拦截的组合确实是"会被拒绝"的，而非测试写错了分支
	if err := ValidateListenerPolicy(string(ListenerTypeTCPReverse), "0.0.0.0",
		&ListenerConfig{AllowLegacyShell: true}); err == nil {
		t.Fatal("变异自检失败：事故组合竟被放行，策略未生效")
	}
	if err := ValidateListenerPolicy(string(ListenerTypeHTTPBeacon), "0.0.0.0",
		&ListenerConfig{}); err == nil {
		t.Fatal("变异自检失败：公网明文 http_beacon 竟被放行，矩阵未生效")
	}
	if err := ValidateListenerPolicy(string(ListenerTypeWebSocket), "0.0.0.0",
		&ListenerConfig{}); err == nil {
		t.Fatal("变异自检失败：公网明文 websocket 竟被放行，矩阵未生效")
	}
	// 且必须不影响正常用法（加密载荷公网监听 + 明文回环监听）
	allowed := []struct {
		name     string
		ltype    string
		bindHost string
		cfg      *ListenerConfig
	}{
		{"加密 Beacon 公网监听", string(ListenerTypeTCPReverse), "0.0.0.0", &ListenerConfig{AllowLegacyShell: false}},
		{"TLS Beacon 公网监听", string(ListenerTypeHTTPSBeacon), "0.0.0.0", &ListenerConfig{}},
		{"明文列表回环监听", string(ListenerTypeHTTPBeacon), "127.0.0.1", &ListenerConfig{}},
		{"websocket 回环监听", string(ListenerTypeWebSocket), "::1", &ListenerConfig{}},
	}
	for _, a := range allowed {
		if err := ValidateListenerPolicy(a.ltype, a.bindHost, a.cfg); err != nil {
			t.Fatalf("反向自检失败：正常用法 %s 被误伤：%v", a.name, err)
		}
	}
}
