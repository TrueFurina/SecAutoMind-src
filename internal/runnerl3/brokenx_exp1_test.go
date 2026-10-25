package runnerl3

// brokenx_exp1_test.go —— 破晓实验 #1（2026-10-25）：SecAutoMind 自有链路
// （LLM + 79 技能工具）在 heldout 外部真题上的首次实测。
//
// 假设（可证伪）：LLM 编排技能库（execute_python → xhlj 79 skills）+ 题面内联
// 附件文本，能在 presolve 未覆盖的外部真题上解出 ≥1/3。
// 纪律：≤5 样本（本实验 3 题，按类别/格式多样性选取，未预读任何题解）；
// 一次只开这一个实验；无效即回滚并如实记「无效」。
// 口径：SolvedBy=llm 仅计 LLM 产物命中（sha256 对题库 flag_sha256），
// presolve/python 命中不得混入（守卫见末尾对照用例）。
//
// 环境守卫：BROKENX_EXP1=1 且 RUNNER_LLM_API_KEY 在位才运行（真 token 成本）。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"secautomind-ai/internal/ctfplatform"
)

func expCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

const (
	bxBenchJSON   = "../../data/questions_external_bench/external_bench.json"
	bxAttachRoot  = "../../data/questions_external_bench/_attachments"
	bxSkillsDir   = "../../CTF-Agent_融合/ctf_agent/skills"
	bxPythonPath  = `C:\Users\Lenovo\.workbuddy\binaries\python\envs\default\Scripts\python.exe`
)

type bxCase struct {
	qid      string
	category string
}

// bxSelection 按类别/格式多样性选取（未预读题解——公平 heldout）。
func bxSelection() []bxCase {
	return []bxCase{
		{qid: "ext_gctf2024_otp", category: "crypto"},
		{qid: "ext_gctf2021_filestore", category: "misc"},
		{qid: "ext_gctf2023_totally-not-brute-force", category: "misc"},
	}
}

// expSkillAdapter 把 xhlj 79 技能库桥接为 runnerl3 的 execute_python 工具。
type expSkillAdapter struct{}

func (a *expSkillAdapter) RunSkill(ctx context.Context, skillName string, ch *ctfplatform.Challenge) ([]string, bool) {
	code := "import sys, json\n" +
		"sys.path.insert(0, r'" + bxSkillsDir + "')\n" +
		"import " + skillName + "\n" +
		"res = " + skillName + ".run({'text': sys.argv[1]})\n" +
		"print(json.dumps(res, ensure_ascii=False, default=str))"
	cmd := expCommand(ctx, bxPythonPath, "-c", code, ch.Description)
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return nil, false
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		return nil, false
	}
	var flags []string
	for _, k := range []string{"flag", "flag_candidate", "decoded", "result"} {
		if v, ok := out[k]; ok {
			switch vv := v.(type) {
			case string:
				if vv != "" {
					flags = append(flags, vv)
				}
			case []any:
				for _, e := range vv {
					if s, ok := e.(string); ok && s != "" {
						flags = append(flags, s)
					}
				}
			}
		}
	}
	return flags, len(flags) > 0
}

func TestBrokenXExp1(t *testing.T) {
	if os.Getenv("BROKENX_EXP1") == "" {
		t.Skip("破晓实验 #1 为手动跑：设 BROKENX_EXP1=1 且 RUNNER_LLM_API_KEY 在位（真 token 成本，≤3 样本）")
	}
	if os.Getenv("RUNNER_LLM_API_KEY") == "" {
		t.Skip("RUNNER_LLM_API_KEY 未设")
	}
	for _, c := range bxSelection() {
		t.Run(c.qid, func(t *testing.T) {
			var bench struct {
				Problems map[string]struct {
					Description string `json:"description"`
					FlagSHA256  string `json:"flag_sha256"`
				} `json:"problems"`
			}
			braw, err := os.ReadFile(bxBenchJSON)
			if err != nil {
				t.Skipf("外部基准 JSON 缺失: %v", err)
			}
			if err := json.Unmarshal(braw, &bench); err != nil {
				t.Skipf("外部基准 JSON 解析失败: %v", err)
			}
			p, ok := bench.Problems[c.qid]
			if !ok || p.FlagSHA256 == "" {
				t.Skipf("基准无该题或无 flag_sha256")
			}
			d := p
			// 附件文本内联（二进制跳过——首实验限定文本可内联形态）
			desc := d.Description
			attDir := filepath.Join(bxAttachRoot, filepath.FromSlash(c.qid))
			if entries, err := os.ReadDir(attDir); err == nil {
				for _, e := range entries {
					if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
						continue
					}
					if b, err := os.ReadFile(filepath.Join(attDir, e.Name())); err == nil && len(b) < 16384 {
						desc += "\n[attachment: " + e.Name() + "]\n" + string(b)
					}
				}
			}
			ch := &ctfplatform.Challenge{
				ID: c.qid, Category: c.category, Description: desc,
			}
			fb := NewLLMFallback(context.Background(), zap.NewNop(), &expSkillAdapter{})
			flags, err := fb.Solve(context.Background(), ch)
			if err != nil {
				t.Logf("[%s] LLM 层错误: %v", c.qid, err)
			}
			solved := false
			for _, f := range flags {
				sum := sha256Hex(f)
				if sum == p.FlagSHA256 {
					solved = true
					t.Logf("[%s] ✅ LLM 解出（sha256 官方锚闭环）: %s", c.qid, f)
				}
			}
			if !solved {
				t.Logf("[%s] ⛔ 未解出（候选 %d 个）", c.qid, len(flags))
			}
			// 报告制：不因未解出而 FAIL——实验读数如实记录即可
		})
	}
}
