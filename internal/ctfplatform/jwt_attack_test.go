package ctfplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

type jwtBenchProblem struct {
	FlagSHA256  string `json:"flag_sha256"`
	Description string `json:"description"`
}

func jwtSha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestJWTCandidatesOffline 离线单测：三种攻击变体的伪造结果必须正确（不依赖靶场）。
func TestJWTCandidatesOffline(t *testing.T) {
	// 用弱密钥签一个 guest token 作为观测样本
	secret := []byte("secret123")
	h := jwtHeaderFor("HS256")
	p := jwtB64Enc([]byte(`{"user":"guest","role":"user"}`))
	sample := h + "." + p + "." + jwtHS256(h+"."+p, secret)

	cands := jwtCandidates(sample, nil)
	if len(cands) == 0 {
		t.Fatal("未产出任何伪造候选")
	}

	// 1) 弱密钥重签：存在候选能用 secret123 验签通过，且 role=admin
	okWeak := false
	for _, c := range cands {
		parts := strings.Split(c, ".")
		if len(parts) != 3 {
			continue
		}
		if jwtHS256(parts[0]+"."+parts[1], secret) != parts[2] {
			continue
		}
		claims := jwtB64Dec(parts[1])
		if strings.Contains(string(claims), `"role":"admin"`) {
			okWeak = true
			break
		}
	}
	if !okWeak {
		t.Errorf("弱密钥重签失败：没有可用 secret123 验签且 role=admin 的候选（共 %d 个）", len(cands))
	}

	// 2) alg=none：存在 header alg=none 且签名段为空的候选
	okNone := false
	for _, c := range cands {
		parts := strings.Split(c, ".")
		if len(parts) != 3 {
			continue
		}
		if strings.Contains(strings.ToLower(jwtB64Dec2Str(parts[0])), `"alg":"none"`) && parts[2] == "" {
			okNone = true
			break
		}
	}
	if !okNone {
		t.Error("alg=none 伪造失败：缺少 header alg=none 且签名为空的候选")
	}

	// 3) 公钥混淆：用公钥字节签的样本 → 候选应能用同一公钥验签
	pub := []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
	h2 := jwtHeaderFor("HS256")
	p2 := jwtB64Enc([]byte(`{"user":"guest","role":"user"}`))
	sample2 := h2 + "." + p2 + "." + jwtHS256(h2+"."+p2, pub)
	cands2 := jwtCandidates(sample2, [][]byte{pub})
	okPub := false
	for _, c := range cands2 {
		parts := strings.Split(c, ".")
		if len(parts) != 3 {
			continue
		}
		if jwtHS256(parts[0]+"."+parts[1], pub) == parts[2] &&
			strings.Contains(string(jwtB64Dec(parts[1])), `"role":"admin"`) {
			okPub = true
			break
		}
	}
	if !okPub {
		t.Errorf("公钥混淆重签失败（共 %d 个候选）", len(cands2))
	}

	t.Logf("离线单测通过：候选数 弱密钥场景=%d 公钥场景=%d", len(cands), len(cands2))
}

func jwtB64Dec2Str(s string) string { return string(jwtB64Dec(s)) }

// TestJWTAttackAgainstRange 靶场实战机验：三个场景必须真绕过鉴权才拿得到 flag。
func TestJWTAttackAgainstRange(t *testing.T) {
	root := filepath.Join("..", "..")
	rangePy := filepath.Join(root, "data", "ctf_benchmark", "live_target", "jwt_range.py")
	if _, err := os.Stat(rangePy); err != nil {
		t.Skip("jwt_range.py 缺失，跳过")
	}
	raw, err := os.ReadFile(filepath.Join(root, "data", "ctf_benchmark", "jwt_benchmark.json"))
	if err != nil {
		t.Skip("jwt_benchmark.json 缺失（先跑 jwt_range.py --dump-json），跳过")
	}
	var doc struct {
		Problems map[string]jwtBenchProblem `json:"problems"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 JWT 基准集失败: %v", err)
	}

	port := "18090"
	cmd := exec.Command("python", rangePy, port)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动 JWT 靶场失败: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	baseURL := "http://127.0.0.1:" + port
	ready := false
	for i := 0; i < 80; i++ {
		if resp, err := http.Get(baseURL + "/"); err == nil {
			resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("JWT 靶场未就绪")
	}

	ids := make([]string, 0, len(doc.Problems))
	for id := range doc.Problems {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	hit := 0
	for _, id := range ids {
		p := doc.Problems[id]
		hints := ParseWebHints(p.Description)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		flags := AttackJWT(ctx, baseURL, hints)
		cancel()

		got := false
		for _, f := range flags {
			if jwtSha256Hex(f) == p.FlagSHA256 {
				got = true
				break
			}
		}
		if got {
			hit++
			t.Logf("  ✅ %-12s 绕过成功 (%d 个 flag)", id, len(flags))
		} else {
			t.Errorf("  ❌ %-12s 未绕过（解析到端点 %v，返回 %d 个候选 flag）",
				id, hints.Endpoints, len(flags))
		}
	}
	t.Logf("JWT 认证绕过基准：%d/%d", hit, len(ids))
	if hit != len(ids) {
		t.Fatalf("JWT 靶场覆盖率 %d/%d，未达全绿", hit, len(ids))
	}
}

// TestJWTAttackViaProductionText 生产入口机验：题目文本里给 URL，走生产链路自动打。
func TestJWTAttackViaProductionText(t *testing.T) {
	root := filepath.Join("..", "..")
	rangePy := filepath.Join(root, "data", "ctf_benchmark", "live_target", "jwt_range.py")
	raw, err := os.ReadFile(filepath.Join(root, "data", "ctf_benchmark", "jwt_benchmark.json"))
	if _, statErr := os.Stat(rangePy); statErr != nil || err != nil {
		t.Skip("JWT 靶场或基准集缺失，跳过")
	}
	var doc struct {
		Problems map[string]jwtBenchProblem `json:"problems"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	port := "18089"
	cmd := exec.Command("python", rangePy, port)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	baseURL := "http://127.0.0.1:" + port
	ready := false
	for i := 0; i < 80; i++ {
		if resp, err := http.Get(baseURL + "/"); err == nil {
			resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("靶场未就绪")
	}

	ids := make([]string, 0, len(doc.Problems))
	for id := range doc.Problems {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	hit := 0
	for _, id := range ids {
		p := doc.Problems[id]
		text := p.Description + "\n靶机: " + baseURL
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		flags := jwtAttackFromText(ctx, text)
		cancel()
		got := false
		for _, f := range flags {
			if jwtSha256Hex(f) == p.FlagSHA256 {
				got = true
				break
			}
		}
		if got {
			hit++
		} else {
			t.Errorf("生产入口未命中 %s", id)
		}
	}
	t.Logf("生产入口（题目文本→自动打靶）：%d/%d", hit, len(ids))
	if hit != len(ids) {
		t.Fatalf("生产入口 %d/%d 未全绿", hit, len(ids))
	}
}

// TestJWTSolverRegistered 反注水门禁：JWT 求解器必须真实注册进生产注册表。
func TestJWTSolverRegistered(t *testing.T) {
	found := false
	for _, s := range GetSolvers() {
		if s.Name == "jwt_auth_bypass" {
			found = true
			if !s.Enabled {
				t.Error("jwt_auth_bypass 已注册但未启用")
			}
			break
		}
	}
	if !found {
		t.Fatal("jwt_auth_bypass 未注册到生产注册表——会变成宣称有、实际不跑的注水求解器")
	}
}
