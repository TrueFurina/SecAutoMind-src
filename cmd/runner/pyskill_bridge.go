// pyskill_bridge.go —— Go 进程通过 subprocess 调 Python skill 的统一桥接。
//
// 为什么存在：
//   SecAutoMind runner 是纯 Go 二进制，但 reverse/pwn 真跑需要 angr/pwntools 等
//   Python 生态。强行 Go 化 angr 等于重造 angr（500MB+，成本爆炸）。
//   正确做法是 Go exec subprocess 桥接——Python skill 保持原样，Go 进程只负责
//   超时控制 + JSON 序列化 + 路由。
//
// 调用协议（与西湖论剑 SkillManager 对齐）：
//   1. 每个 skill.py 必须有 def run(params: dict) -> dict
//   2. Go 进程 exec: python -c "import skill_name; import json; print(json.dumps(skill_name.run(params)))"
//   3. params 通过 --params '<json>' 命令行参数传入
//   4. skill 的 run() 必须返回 dict，Go 从 stdout 读 JSON
//   5. 超时默认 30s（angr 符号执行可能慢，可调）
//
// 依赖检查（必须做，否则 subprocess 挂死）：
//   - angr: pip show angr → 2>&1 | grep -q "No matching" 则跳过
//   - pwntools: pip show pwntools 同理
//   - 任何 subprocess 调工具（bkcrack/PARI/GP）也先检查工具存在
//
// 注意：桥接只做"有依赖 → 跑 → 拿 flag"，不做 LLM 编排。
// LLM fallback 留到赛后——直接 einoopenai.NewChatModel().Generate()，
// 只绑最小工具集（execute + read_file），不起 agent/db 全链路。

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"

	"secautomind-ai/internal/ctfplatform"
)

// pySkillRunner 通过 subprocess 调 Python skill。
type pySkillRunner struct {
	pythonPath   string            // Python 解释器路径
	skillsDir    string            // skills/ 目录绝对路径
	timeout      time.Duration     // 单次执行超时
	hasAngr      bool              // angr 是否已装（启动时检查一次）
	hasPwnTools  bool              // pwntools 是否已装
	logger       *zap.Logger
	skillCatalog map[string][]string // category → skill filename 列表（只列"真跑"skill）
}

// newPySkillRunner 初始化 bridge。启动时检查一次关键依赖，避免每次调用都 pip show。
func newPySkillRunner(ctx context.Context, logger *zap.Logger) *pySkillRunner {
	// pythonPath: env 覆盖优先，默认用 workbuddy 那条绝对路径（本环境 python 不在 PATH）
	pyPath := osGetenv("CTF_PYTHON_PATH")
	if pyPath == "" {
		// 多平台 fallback：优先 python3（Linux/macOS），其次 python，最后 Windows venv 默认
		candidates := []string{"python3", "python", `C:\Users\Lenovo\.workbuddy\binaries\python\envs\default\Scripts\python.exe`}
		for _, c := range candidates {
			if _, err := execLookPath(c); err == nil {
				pyPath = c
				break
			}
		}
		if pyPath == "" {
			pyPath = "python3" // 兜底，运行时会报错但不会 panic
		}
	}

	r := &pySkillRunner{
		pythonPath: pyPath,
		timeout:    30 * time.Second,
		logger:     logger,
		skillCatalog: map[string][]string{
			// 只列"真跑"skill（有 subprocess / angr / pwntools 调用）
			// 提示词范式 skill 不在这里——它们返回流程指引不是 flag
			"crypto": {
				"crypto_complex_mult_group", // 复数乘法群 RSA（需 factordb + PARI/GP）
				"crypto_zip_bkcrack",        // ZIP 明文攻击（需 bkcrack CLI）
			},
			"reverse": {
				"reverse_angr_solver",   // angr 符号执行（需 angr + z3）
				"rev_const_compare",     // 常量比较 reverse（subprocess 调工具）
			},
			"pwn": {
				"pwn_ret2dlresolve",     // ret2dlresolve（需 pwntools）
				"pwn_sandbox_escape",    // 沙箱逃逸（subprocess）
			},
			"misc": {
				"misc_grid_resample",   // 网格重采样（subprocess）
				"misc_zip_fake_encryption", // ZIP 假加密（subprocess）
				"jpeg_png_embedded",    // 图片嵌入（subprocess）
				"svg_path_text",        // SVG 路径文本（subprocess）
			},
		},
	}

	// skills/ 目录：env 覆盖优先，其次多路径 fallback 探测
	// （西湖论剑源仓库不强制必须存在，未来可完全迁出）
	if dir := strings.TrimSpace(osGetenv("CTF_SKILLS_DIR")); dir != "" {
		r.skillsDir = dir
	} else {
		r.skillsDir = findSkillsDir()
	}

	// 依赖检查（一次性）
	r.hasAngr = r.checkDep(ctx, "angr")
	r.hasPwnTools = r.checkDep(ctx, "pwnlib") // pip 包名 pwntools，但 Python import 是 pwn / pwnlib

	logger.Info("Python skill bridge 初始化",
		zap.String("python", r.pythonPath),
		zap.String("skills_dir", r.skillsDir),
		zap.Bool("angr", r.hasAngr),
		zap.Bool("pwntools", r.hasPwnTools))

	return r
}

// osGetenv 包装，避免直接 import os（go vet 要求只在 main import os）
func osGetenv(key string) string {
	v, _ := os.LookupEnv(key)
	return strings.TrimSpace(v)
}

func osGetwd() (string, error) { return os.Getwd() }
func osStat(name string) (os.FileInfo, error) { return os.Stat(name) }
func execLookPath(file string) (string, error) { return exec.LookPath(file) }

// checkDep pip show <name> 退出码 0 = 已装
func (r *pySkillRunner) checkDep(ctx context.Context, name string) bool {
	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx2, r.pythonPath, "-c",
		fmt.Sprintf("import importlib.util; print('OK' if importlib.util.find_spec(%q) else 'MISSING')", name))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "OK")
}

// tryCategory 对指定 category 依次跑"真跑"skill，第一个返回 solved=True 且有 flag 的就用。
// 返回值：(flag candidates, 是否找到)
func (r *pySkillRunner) tryCategory(ctx context.Context, category string, ch *ctfplatform.Challenge) ([]string, bool) {
	skills, ok := r.skillCatalog[category]
	if !ok || len(skills) == 0 {
		return nil, false
	}

	r.logger.Debug("尝试 Python skill 求解",
		zap.String("category", category),
		zap.String("challenge", ch.Title),
		zap.Strings("skills", skills))

	for _, skillName := range skills {
		// 依赖门控
		switch skillName {
		case "reverse_angr_solver":
			if !r.hasAngr {
				continue
			}
		case "pwn_ret2dlresolve", "pwn_sandbox_escape":
			if !r.hasPwnTools {
				continue
			}
		}

		flags, ok := r.runSkill(ctx, skillName, ch)
		if ok && len(flags) > 0 {
			return flags, true
		}
	}
	return nil, false
}

// runSkill subprocess 调单个 Python skill，返回 (flag candidates, 是否成功)
func (r *pySkillRunner) runSkill(ctx context.Context, skillName string, ch *ctfplatform.Challenge) ([]string, bool) {
	params := map[string]interface{}{
		"name":        ch.Title,
		"category":    ch.Category,
		"description": ch.Description,
	}
	if len(ch.AttachmentURLs) > 0 {
		params["attachment_urls"] = ch.AttachmentURLs
	}

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		r.logger.Warn("skill 参数序列化失败", zap.String("skill", skillName), zap.Error(err))
		return nil, false
	}

	// python -c "import sys; sys.path.insert(0, skills_dir); import skill_name; import json; print(json.dumps(skill_name.run(json.loads(sys.argv[1]))))"
	script := fmt.Sprintf(
		"import sys, json; sys.path.insert(0, %q); import %s as s; print(json.dumps(s.run(json.loads(sys.argv[1]))))",
		r.skillsDir, skillName)

	ctx2, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx2, r.pythonPath, "-c", script, string(paramsJSON))
	out, err := cmd.CombinedOutput()

	if ctx2.Err() == context.DeadlineExceeded {
		r.logger.Warn("skill 超时", zap.String("skill", skillName), zap.Duration("timeout", r.timeout))
		return nil, false
	}
	if err != nil {
		r.logger.Debug("skill 执行失败",
			zap.String("skill", skillName),
			zap.Error(err),
			zap.String("stderr", string(out)))
		return nil, false
	}

	// 解析 JSON 返回值
	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		// 有些 skill 可能返回 list 或直接字符串
		r.logger.Debug("skill 返回值非 dict", zap.String("skill", skillName), zap.String("raw", string(out)))
		return nil, false
	}

	// 提取 flag
	solved, _ := result["solved"].(bool)
	ok, _ := result["ok"].(bool)
	if solved || ok {
		if flag, ok := result["flag"].(string); ok && flag != "" {
			return []string{flag}, true
		}
		if flags, ok := result["flags"].([]interface{}); ok {
			out := make([]string, 0, len(flags))
			for _, f := range flags {
				if s, ok := f.(string); ok && s != "" {
					out = append(out, s)
				}
			}
			if len(out) > 0 {
				return out, true
			}
		}
		// 有些 skill 返回 flow/note 但没 flag——不算成功
	}

	return nil, false
}

// findSkillsDir 多路径 fallback 探测 Python skills 目录
// 按优先级依次尝试：
//  1. $PWD/internal/ctfplatform/pyskills/         （SecAutoMind 仓库内未来迁出位置）
//  2. $PWD/skills/python/                        （另一个可能的仓库内位置）
//  3. E:\Program\西湖论剑\ctf_agent\skills       （源仓库——可能已被删除）
//  4. $PWD/CTF-Agent_融合/ctf_agent/skills       （归档副本）
//
// 返回第一个存在的目录路径；都不存在则返回空串（runner 会跳过 Layer 2）。
func findSkillsDir() string {
	for _, dir := range candidateSkillDirs() {
		if dir == "" {
			continue
		}
		info, err := osStat(dir)
		if err == nil && info.IsDir() {
			return dir
		}
	}
	return ""
}

// candidateSkillDirs 列出所有候选路径（不做存在性判断，方便测试）
func candidateSkillDirs() []string {
	cwd, _ := osGetwd()
	var dirs []string

	if cwd != "" {
		dirs = append(dirs,
			cwd+`\internal\ctfplatform\pyskills`,
			cwd+`\skills\python`,
			cwd+`\CTF-Agent_融合\ctf_agent\skills`,
		)
	}

	// 西湖论剑源仓库（可能不存在，不影响其他候选）
	dirs = append(dirs, `E:\Program\西湖论剑\ctf_agent\skills`)

	return dirs
}
