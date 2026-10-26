package ctfplatform

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// ───────────────────────── fakePlatform：可配置的生产接线测试桩 ─────────────────────────

type fakePlatform struct {
	list       []Challenge
	byID       map[string]*Challenge
	created    []string
	accessed   []string
	downloaded []string
	submitted  int
	// submittedFlags 记录实际提交的候选（P1-4 真值仲裁需要断言"提交了什么"，
	// 只数次数无法区分"拦住了错的"和"提交了错的"）。
	submittedFlags []string
	accessURL      string
}

func (f *fakePlatform) ListChallenges(ctx context.Context) ([]Challenge, error) { return f.list, nil }
func (f *fakePlatform) GetChallenge(ctx context.Context, id string) (*Challenge, error) {
	if ch, ok := f.byID[id]; ok {
		return ch, nil
	}
	return nil, nil
}
func (f *fakePlatform) CreateInstance(ctx context.Context, id string) (*Instance, error) {
	f.created = append(f.created, id)
	return &Instance{InstanceID: id}, nil
}
func (f *fakePlatform) GetAccess(ctx context.Context, id string) (*Access, error) {
	f.accessed = append(f.accessed, id)
	return &Access{URL: f.accessURL}, nil
}
func (f *fakePlatform) DownloadAttachment(ctx context.Context, id string) ([]string, error) {
	f.downloaded = append(f.downloaded, id)
	return []string{filepath.Join(os.TempDir(), "fake_att.txt")}, nil
}
func (f *fakePlatform) SubmitFlag(ctx context.Context, id, flag string) (*SubmitResult, error) {
	f.submitted++
	f.submittedFlags = append(f.submittedFlags, flag)
	return &SubmitResult{Accepted: true, Correct: true}, nil
}
func (f *fakePlatform) ResetInstance(ctx context.Context, id string) error   { return nil }
func (f *fakePlatform) DestroyInstance(ctx context.Context, id string) error { return nil }
func (f *fakePlatform) GetMatchInfo(ctx context.Context) (map[string]interface{}, error) {
	return nil, nil
}
func (f *fakePlatform) GetOverview(ctx context.Context) (map[string]interface{}, error) {
	return nil, nil
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// ───────────────────────── 任务1：HasInstance 兜底双保险 ─────────────────────────
//
// 场景：仅开 AutoBuildEnv、不开 AutoFetchDetail，且列表接口不返回 has_instance。
// 兜底逻辑应在建靶机前自行调 GetChallenge 补全 HasInstance，使靶机真正建起。
func TestHasInstanceFallbackBuildsEnv(t *testing.T) {
	fp := &fakePlatform{
		list:      []Challenge{{ID: "3001", HasInstance: false, Category: "web"}},
		byID:      map[string]*Challenge{"3001": {ID: "3001", HasInstance: true, Category: "web"}},
		accessURL: "http://127.0.0.1:8080",
	}
	pc := DefaultPollerConfig()
	pc.AutoBuildEnv = true
	pc.AutoFetchDetail = false // 关键：不开 FetchDetail，完全依赖兜底
	// solver 不产出 flag（只验证接线：兜底是否真建了靶机）
	p := NewPoller(fp, SolverFunc(func(_ context.Context, _ *Challenge) ([]string, error) {
		return nil, nil
	}), pc, zap.NewNop())

	if _, err := p.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce 失败: %v", err)
	}

	if !contains(fp.created, "3001") {
		t.Fatalf("HasInstance 兜底未建靶机：created=%v（静默 0 分翻车未修复）", fp.created)
	}
	if !contains(fp.accessed, "3001") {
		t.Fatalf("建靶机后未取访问地址：accessed=%v", fp.accessed)
	}
}

// ───────────────────────── 任务2：DownloadAttachment 真实骨架 ─────────────────────────

func TestExtractAttachmentURLs(t *testing.T) {
	m := map[string]json.RawMessage{
		"attachment": json.RawMessage(`{"url":"http://x/a.bin"}`),
		"file":       json.RawMessage(`"http://x/b.bin"`),
		"attachments": json.RawMessage(`[{"downloadUrl":"http://x/c.bin"},"http://x/d.bin"]`),
	}
	urls := extractAttachmentURLs(m, "详情见 http://x/e.bin")
	want := map[string]bool{
		"http://x/a.bin": true, "http://x/b.bin": true, "http://x/c.bin": true,
		"http://x/d.bin": true, "http://x/e.bin": true,
	}
	if len(urls) != len(want) {
		t.Fatalf("期望 %d 个 URL，得 %d: %v", len(want), len(urls), urls)
	}
	for _, u := range urls {
		if !want[u] {
			t.Fatalf("意外 URL: %s（全部=%v）", u, urls)
		}
	}
}

func TestDownloadURLsToDir(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("PCAP-BINARY-CONTENT"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	paths, err := downloadURLsToDir(context.Background(), &http.Client{}, []string{srv.URL + "/evi.pcap"}, dir)
	if err != nil {
		t.Fatalf("下载失败: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("期望落盘 1 个文件，得 %d: %v", len(paths), paths)
	}
	data, rerr := os.ReadFile(paths[0])
	if rerr != nil || string(data) != "PCAP-BINARY-CONTENT" {
		t.Fatalf("落盘内容错误: err=%v data=%q", rerr, string(data))
	}
}

// 非 http(s) / 穿越路径必须被拒（安全约束）
func TestDownloadURLsToDirRejectsUnsafe(t *testing.T) {
	dir := t.TempDir()
	paths, _ := downloadURLsToDir(context.Background(), &http.Client{},
		[]string{"file:///etc/passwd", "ftp://x/y", "../../escape.bin"}, dir)
	if len(paths) != 0 {
		t.Fatalf("不安全 URL 不应落盘：%v", paths)
	}
}

// ───────────────────────── 任务3：Integrator 可选建靶机前置 ─────────────────────────

func TestIntegratorPrepareChallenge(t *testing.T) {
	fp := &fakePlatform{
		byID: map[string]*Challenge{
			"1001": {ID: "1001", HasInstance: true, HasAttachment: true, Category: "web"},
		},
		accessURL: "http://127.0.0.1:9999",
	}
	integ := NewPresolveAgentIntegrator(NewPresolver(zap.NewNop()), NewTaskAnalyzer(), fp, zap.NewNop())

	// ① 空 challengeID → by-design 不激活，返回 nil
	if ch, _ := integ.PrepareChallenge(context.Background(), ""); ch != nil {
		t.Fatal("空 challengeID 应返回 nil（默认不激活建靶机）")
	}

	// ② 有 challengeID → 拉详情 + 建靶机 + 取地址 + 下附件，注入描述
	ch, err := integ.PrepareChallenge(context.Background(), "1001")
	if err != nil {
		t.Fatalf("PrepareChallenge 失败: %v", err)
	}
	if ch == nil {
		t.Fatal("应返回 Challenge")
	}
	if _, ok := ch.Extra["target_url"]; !ok {
		t.Fatal("未注入靶机地址到 Extra")
	}
	if !strings.Contains(ch.Description, "靶机地址") {
		t.Fatal("描述未含靶机地址标记")
	}
	if !contains(fp.created, "1001") {
		t.Fatal("未调用 CreateInstance 建靶机")
	}
	if !contains(fp.downloaded, "1001") {
		t.Fatal("未调用 DownloadAttachment 下附件")
	}
}

func TestIntegratorPrepareChallengeNilPlatform(t *testing.T) {
	integ := NewPresolveAgentIntegrator(NewPresolver(zap.NewNop()), NewTaskAnalyzer(), nil, zap.NewNop())
	if _, err := integ.PrepareChallenge(context.Background(), "1001"); err == nil {
		t.Fatal("平台未接线应返回错误")
	}
}

// ───────────────────────── 任务3 续：机器人挑战ID提取 + 自动准备流 ─────────────────────────

func TestExtractChallengeRef(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"帮我解题 题号3001", "3001"},
		{"编号: 3002", "3002"},
		{"题目编号 3003", "3003"},
		{"challenge id 3004", "3004"},
		{"exercise_id 3005", "3005"},
		{"#3006 这道题", "3006"},
		{"题目 3007 求旗", "3007"},
		{"这道题很难但没有编号和题号", ""},
		{"#12 太短不应匹配", ""}, // 仅 #三位数以上 才匹配
		{"题号abc 非数字", ""},
	}
	for _, c := range cases {
		if got := ExtractChallengeRef(c.in); got != c.want {
			t.Errorf("ExtractChallengeRef(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestRobotAutoPrepareFlow 模拟 agent.go 机器人钩子：从消息提取 challengeID → PrepareChallenge →
// 把靶机地址/附件标记注入描述。验证「决赛时机器人自动建靶机 + 下附件」端到端闭环（用 fakePlatform 替身，
// 不含真实平台调用；真机联调仍待官方凭证）。
func TestRobotAutoPrepareFlow(t *testing.T) {
	fp := &fakePlatform{
		byID: map[string]*Challenge{
			"3001": {ID: "3001", HasInstance: true, HasAttachment: true, Description: "原始题面"},
		},
		accessURL: "http://10.0.0.1:8080",
	}
	integ := NewPresolveAgentIntegrator(NewPresolver(zap.NewNop()), NewTaskAnalyzer(), fp, zap.NewNop())

	ref := ExtractChallengeRef("帮我解题 题号3001")
	if ref != "3001" {
		t.Fatalf("提取 challengeID 失败: %q", ref)
	}
	ch, err := integ.PrepareChallenge(context.Background(), ref)
	if err != nil {
		t.Fatalf("PrepareChallenge 失败: %v", err)
	}
	if !strings.Contains(ch.Description, "http://10.0.0.1:8080") {
		t.Errorf("靶机地址未注入描述: %q", ch.Description)
	}
	if !strings.Contains(ch.Description, "[用户上传的文件]") {
		t.Errorf("附件标记未注入描述: %q", ch.Description)
	}
	if !contains(fp.created, "3001") {
		t.Error("未触发建靶机（CreateInstance）")
	}
	if !contains(fp.downloaded, "3001") {
		t.Error("未触发下附件（DownloadAttachment）")
	}
}

// ───────────────────────── 赛时吞吐：静态优先排序 ─────────────────────────
//
// 快闪赛 60 分钟 19 题：无需靶机的静态题（presolve 秒级）必须先于靶机题处理，
// 否则 CreateInstance 启动延迟会拖慢整条解题流水线。排序为纯函数，直接断言。

func TestSortChallengesStaticFirst(t *testing.T) {
	in := []Challenge{
		{ID: "env1", HasInstance: true, Category: "web", Description: "需靶机的 web 题"},
		{ID: "s1", HasInstance: false, Category: "crypto", Description: "静态题 1"},
		{ID: "env2", HasInstance: true, Category: "pwn", Description: "需靶机的 pwn 题"},
		{ID: "s2", HasInstance: false, Category: "misc", Description: "静态题 2"},
	}
	sortChallengesStaticFirst(in)
	want := []string{"s1", "s2", "env1", "env2"} // 静态在前（稳定保序），靶机在后
	if len(in) != len(want) {
		t.Fatalf("排序后长度 = %d, want %d", len(in), len(want))
	}
	for i := range want {
		if in[i].ID != want[i] {
			t.Fatalf("排序错误: got %v, want %v（静态题必须先于靶机题）", idsOf(in), want)
		}
	}
}

func idsOf(chs []Challenge) []string {
	out := make([]string, 0, len(chs))
	for _, c := range chs {
		out = append(out, c.ID)
	}
	return out
}
