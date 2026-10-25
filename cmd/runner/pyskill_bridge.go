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
	hasCrypto    bool              // pycryptodome / cryptography 是否已装
	logger       *zap.Logger
	skillCatalog map[string][]string // category → skill filename 列表（全量 79 skill）
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
			// 扩到全量 79 skill（2026-10-25 gap 分析：之前硬编码只有 10 个，Runner L2 实际只跑这 10 个）
			// 所有 skill 都有 def run(params: dict) 接口；依赖门控在 tryCategory 里做
			// 前缀 → Runner Category 映射见 candidateSkillDirs 注释 + gap 分析记录
			"crypto": {
				"base64_multilayer", "caesar_bruteforce", "crypto_complex_mult_group",
				"crypto_coppersmith", "crypto_cycling", "crypto_ecb_block_attack",
				"crypto_electric_mayhem_cls", "crypto_enigma_crib", "crypto_h1_buggy_rng",
				"crypto_hastad_broadcast", "crypto_high_exponent", "crypto_keyboard_path",
				"crypto_knapsack_mhk", "crypto_lattice_attack", "crypto_lcg_recover",
				"crypto_legendre_phi", "crypto_modinv_factor", "crypto_pkcs1_improved",
				"crypto_pkcs1_padding_oracle", "crypto_primes_subset", "crypto_zip_bkcrack",
				"hash_crack", "rsa_fermat_factor", "vigenere_decode",
				"zip_chain_decode", "zip_crypto_bruteforce", "zip_fake_encryption",
				"zip_filename_chain_decode",
			},
			"web": {
				"java_deserialization_flow", "java_nashorn_response", "php_unserialize_pop",
				"source_audit_patterns", "ssti_detect", "web_jwt_prototype",
				"web_multi_step_chain", "web_race_condition", "web_second_order_injection",
				"web_source_audit", "web_sqli", "web_ssrf", "web_target_interact",
				"web_upload_bypass", "web_xxe_file_read",
			},
			"pwn": {
				"pwn_exploit_flow", "pwn_libc_fingerprint", "pwn_nogdb_flow",
				"pwn_ret2dlresolve", "pwn_sandbox_escape", "pwn_tcache_safelinking",
			},
			"reverse": {
				"pyc_decompile", "rev_const_compare", "rev_xor_verify",
				"reverse_angr_solver", "reverse_elf_general", "reverse_go_apk",
				"reverse_js_methodology", "reverse_obfuscation", "reverse_router",
			},
			"misc": {
				"banana_script", "emoji_binary", "jpeg_png_embedded", "lfsr_filter_recover",
				"mbr_sse_verify", "misc_bigfile_analysis", "misc_bigfile_traffic",
				"misc_deflate_huffman_flag", "misc_disk_forensics", "misc_grid_resample",
				"misc_jpeg_padding_stego", "misc_pcap_ezrat_chat", "misc_qr_matrix",
				"misc_traffic_analysis", "misc_zip_fake_encryption", "morse_ab_decode",
				"morse_decoder", "pcap_http_carve", "svg_path_text", "task_analyzer",
				"thoroughlystripped",
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
	// Crypto 依赖：pycryptodome (import Crypto) 或 cryptography (import cryptography)，任一存在即可
	r.hasCrypto = r.checkDep(ctx, "Crypto") || r.checkDep(ctx, "cryptography")

	logger.Info("Python skill bridge 初始化",
		zap.String("python", r.pythonPath),
		zap.String("skills_dir", r.skillsDir),
		zap.Int("catalog_size", totalSkills(r.skillCatalog)),
		zap.Bool("angr", r.hasAngr),
		zap.Bool("pwntools", r.hasPwnTools),
		zap.Bool("crypto", r.hasCrypto))

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

// totalSkills 返回 skillCatalog 总 skill 数（辅助 logger 输出）
func totalSkills(cat map[string][]string) int {
	n := 0
	for _, v := range cat {
		n += len(v)
	}
	return n
}

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
		// 依赖门控（2026-10-25 扩：加 NeedCrypto，覆盖 crypto_* skill 大部分）
		switch skillName {
		case "reverse_angr_solver":
			if !r.hasAngr {
				continue
			}
		case "pwn_ret2dlresolve", "pwn_nogdb_flow", "pwn_sandbox_escape", "pwn_exploit_flow":
			if !r.hasPwnTools {
				continue
			}
		// Crypto 类 skill：大部分依赖 pycryptodome / cryptography
		case "crypto_complex_mult_group", "crypto_coppersmith", "crypto_ecb_block_attack",
			"crypto_electric_mayhem_cls", "crypto_h1_buggy_rng", "crypto_hastad_broadcast",
			"crypto_high_exponent", "crypto_lcg_recover", "crypto_legendre_phi",
			"crypto_pkcs1_improved", "crypto_pkcs1_padding_oracle", "crypto_zip_bkcrack",
			"rsa_fermat_factor":
			if !r.hasCrypto {
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

	// python -c 脚本：包装 bytes 返回值为 base64 dict（防止 json.dumps 崩溃）
	// 2026-10-25 gap 分析：约 20 个 skill 返回 bytes（crypto_hastad_broadcast 等），json.dumps 对 bytes 会直接崩溃
	script := fmt.Sprintf(
		"import sys, json, base64; sys.path.insert(0, %q); import %s as s; _r = s.run(json.loads(sys.argv[1])); _r = {\"__base64__\": base64.b64encode(_r).decode()} if isinstance(_r, bytes) else _r; print(json.dumps(_r))",
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

	// __base64__ 键 = Python 端检测到原返回值是 bytes，包装成 base64 dict
	// bytes 返回值通常是二进制结果，不含 flag 字符串，直接跳过
	if _, isB64 := result["__base64__"]; isB64 {
		r.logger.Debug("skill 返回 bytes（已 base64 包装），跳过", zap.String("skill", skillName))
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
//  1. $PWD/internal/ctfplatform/pyskills/         （SecAutoMind 仓库内，未来迁出位置）
//  2. $PWD/skills/python/                        （仓库内备选位置）
//  3. $PWD/CTF-Agent_融合/ctf_agent/skills       （西湖论剑归档副本——唯一权威来源）
//
// 返回第一个存在的目录路径；都不存在则返回空串（runner 会跳过 Layer 2）。
//
// 【吞并收口 2026-10-25】原第 4 条硬编码路径 `E:\Program\西湖论剑\ctf_agent\skills` 已删除。理由：
//   ① **死候选**：归档副本排在它前面且恒存在，那条永远不会命中；
//   ② **注释与代码曾经顺序相反**（注释说源仓第 3、归档第 4，代码正好颠倒），
//      留着只会继续误导后来人；
//   ③ 它是「西湖论剑尚未彻底并入」在运行链上的**唯一残留**——删掉之后，
//      "把 E:\Program\西湖论剑 整个删掉、本项目功能不受影响"才成为可验证的事实。
//
// 不变量由 pyskill_bridge_test.go::TestCandidateSkillDirsAreRepoLocal 锁住：
// **候选目录一律不得含仓库外绝对路径**。
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
//
// 所有候选都必须由 cwd 派生（仓库内相对路径），**不得出现硬编码的外部绝对路径**。
// 这条约束是「唯一主体」在运行层的落地，由 TestCandidateSkillDirsAreRepoLocal 强制。
func candidateSkillDirs() []string {
	cwd, _ := osGetwd()
	if cwd == "" {
		// 拿不到 cwd 就无法定位仓库，返回空让 findSkillsDir 走 fail-safe（跳过 Layer 2）。
		// 不保留任何外部路径兜底——那正是 2026-10-25 删掉的东西。
		return nil
	}
	return []string{
		cwd + `\internal\ctfplatform\pyskills`,
		cwd + `\skills\python`,
		cwd + `\CTF-Agent_融合\ctf_agent\skills`,
	}
}
