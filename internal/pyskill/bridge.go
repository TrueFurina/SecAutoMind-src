// Package pyskill 是 Go 进程通过 subprocess 调 Python skill 的统一桥接。
//
// 【2026-11-01 迁包】本文件原居于 cmd/runner（package main），导致
// cmd/llmbench / cmd/evalharness 无法复用 —— 这两个跑批入口 pyBridge 恒为 nil，
// 所有"LLM 解题率"数字都只是**无 skill 的纯 LLM 下界**，而生产 runner 的 86 skill
// 通路从未在真机被测过。迁到 internal/pyskill 后两个跑批入口可显式接入
// （llmbench --with-skills），使"带 skill 的生产形态"第一次可被量化。
// 符号改名：New→New、tryCategory→tryCategory（导出名改为 TryCategoryBudget /
// TryCategoryLocal，无限预算的 TryCategory 已于 2026-11-01 删除），
// 其余实现逐字未动（含 2026-11-01 的 skill 名标识符守卫与 procenv 白名单）。
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

package pyskill

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"

	"secautomind-ai/internal/ctfplatform"
	"secautomind-ai/internal/procenv"
)

// Runner 通过 subprocess 调 Python skill。
type Runner struct {
	pythonPath   string        // Python 解释器路径
	skillsDir    string        // skills/ 目录绝对路径
	timeout      time.Duration // 单次执行超时（RunSkill / 模型单点之外的通用兜底）
	// l2Timeout 是 L2 批量扫里**单个 skill** 的上限，默认 120s 而非 30s。
	// 存在原因（2026-11-01 真机冒烟）：crypto_knapsack_mhk 的 mhk2_decrypt 要跑
	// 99.4s，30s 直接把 LLL 类掐死 —— 表现是 "L2-MISS"，实际是超时截断。
	// LLL/格基/因式分解这类正是 crypto 的主力 skill，短超时等于把高价值能力关掉。
	// 总耗时仍由 CTF_L2_BUDGET（整类预算）兜底，所以放宽单点上限不会让单题失控。
	l2Timeout    time.Duration
	richTimeout  time.Duration // 模型显式单点调用（RunSkillRich）的超时，需长
	hasAngr      bool          // angr 是否已装（启动时检查一次）
	hasPwnTools  bool          // pwntools 是否已装
	hasCrypto    bool          // pycryptodome / cryptography 是否已装
	logger       *zap.Logger
	skillCatalog map[string][]string // category → skill filename 列表（全量 79 skill）
	// skillContracts: skill 名 → 它从 params 里读哪些键（逗号分隔，字典序）。
	// 存在原因（2026-11-01 第二层缺口）：Desc 修好之后模型会用真名调 skill 了，
	// 但实测它传的是 {"a1": [], "a2": [], "b": [], "c": []} —— 全是空数组。
	// 名字对了、参数全错，等于还是零。契约必须让模型看得见。
	// 抽取方式：启动时一个 python 子进程 ast 解析每个 skill 文件的
	// params.get("x") / params["x"]，单一真值源 = skill 源码本身（禁止手写）。
	// 抽取失败 → 留空 map，Desc 退化为只列名字（不回归、不影响可用性）。
	skillContracts map[string]skillContract
}

// New 初始化 bridge。启动时检查一次关键依赖，避免每次调用都 pip show。
func New(ctx context.Context, logger *zap.Logger) *Runner {
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

	r := &Runner{
		pythonPath:  pyPath,
		timeout:     durFromEnv("CTF_SKILL_TIMEOUT", 30*time.Second),
		l2Timeout:   durFromEnv("CTF_L2_SKILL_TIMEOUT", 120*time.Second),
		richTimeout: durFromEnv("CTF_SKILL_TIMEOUT_RICH", 180*time.Second),
		logger:      logger,
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

	// 参数契约抽取（一次性，失败不致命）
	r.skillContracts = r.probeSkillContracts(ctx)

	logger.Info("Python skill bridge 初始化",
		zap.String("python", r.pythonPath),
		zap.String("skills_dir", r.skillsDir),
		zap.Int("catalog_size", totalSkills(r.skillCatalog)),
		zap.Int("contracts", len(r.skillContracts)),
		zap.Bool("angr", r.hasAngr),
		zap.Bool("pwntools", r.hasPwnTools),
		zap.Bool("crypto", r.hasCrypto))

	return r
}

// SkillsDir 返回实际解析到的 skills 目录；**空串表示没找到**，此时 L2 会静默跳过。
// 调用方（尤其跑批入口）必须对它做显式告警 —— 2026-11-01 的"附件从未落盘
// 40/40 被静默阉割"就是同型事故：能力没接上却不报错，报告看起来像"模型不会做"。
func (r *Runner) SkillsDir() string { return r.skillsDir }

// CatalogSize 返回可路由 skill 总数（category 展开后）。
func (r *Runner) CatalogSize() int { return totalSkills(r.skillCatalog) }

// SkillCatalog 返回 skill 路由表的**副本**，供 L3 渲染 execute_python 的工具描述。
//
// 存在原因（2026-11-01 P0 实锤）：工具描述里原有一张手写 skill 名清单，与
// skillCatalog 早已脱节 —— 列出的 16 个名字 15 个不存在（factor_integer /
// rsa_wiener_attack / angr_decompile / pwn_checksec …），真实 79 个反而一个没写。
// 模型忠实地照描述去调 factor_integer，必然 import 失败 ⇒ skill 通路形同虚设。
// 单一真值源：清单只能从本方法现取，禁止再手写。
// 返回副本，避免调用方改动内部路由表。
func (r *Runner) SkillCatalog() map[string][]string {
	out := make(map[string][]string, len(r.skillCatalog))
	for k, v := range r.skillCatalog {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// skillContract 是单个 skill 从源码里抽出来的"调用契约"。
//
// Params：它从 params 读哪些键（模型必须按这些键传值，缺一个就 KeyError）。
// Dispatch：语义分派参数 → 候选值（如 kind: [mhk2_decrypt, recover_key]）。
// L2 通用路由没法猜 kind 这种语义参数，只能按源码里的 if kind == "..." 分支逐个试。
type skillContract struct {
	Params   string              `json:"params,omitempty"`
	Dispatch map[string][]string `json:"dispatch,omitempty"`
}

// SkillContracts 返回 skill 名 → 参数键列表（逗号分隔，字典序），供 Desc 渲染。
//
// 存在原因（2026-11-01 第二层缺口，真机实测）：Desc 换成真名之后，模型确实
// 改用了 crypto_knapsack_mhk（真名），但 params 传的是
// {"a1": [], "a2": [], "b": [], "c": []} —— 名字对了、参数全错，结果仍是零。
// 模型没法从名字猜出这个 skill 要 pk/ct/kind。契约必须显式给出。
// 返回副本，避免调用方改动内部表。
func (r *Runner) SkillContracts() map[string]string {
	out := make(map[string]string, len(r.skillContracts))
	for k, v := range r.skillContracts {
		if v.Params != "" {
			out[k] = v.Params
		}
	}
	return out
}

// SkillDispatch 返回 skill 名 → 分派参数候选值（L2 逐个试）。
func (r *Runner) SkillDispatch() map[string]map[string][]string {
	out := make(map[string]map[string][]string, len(r.skillContracts))
	for k, v := range r.skillContracts {
		if len(v.Dispatch) == 0 {
			continue
		}
		cp := make(map[string][]string, len(v.Dispatch))
		for dk, dv := range v.Dispatch {
			cp[dk] = append([]string(nil), dv...)
		}
		out[k] = cp
	}
	return out
}

// probeSkillContracts 用**一个** python 子进程 ast 解析各 skill 文件，抽两样东西：
// ① params.get("x") / params["x"] 的键；
// ② 分派分支：`k = params.get("kind")` 之后出现的 `k == "lit"` ⇒ kind 的候选值。
//
// 单一真值源 = skill 源码本身，禁止手写清单（第一层 P0 就是手写清单导致的：
// 16 个名字 15 个不存在）。失败一律返回 nil：Desc 退化为只列名字、L2 也不试分派，
// 等于修复前行为，不阻塞启动。
func (r *Runner) probeSkillContracts(ctx context.Context) map[string]skillContract {
	if r.skillsDir == "" {
		return nil
	}
	names := make([]string, 0, totalSkills(r.skillCatalog))
	for _, v := range r.skillCatalog {
		names = append(names, v...)
	}
	if len(names) == 0 {
		return nil
	}
	namesJSON, err := json.Marshal(names)
	if err != nil {
		return nil
	}

	const probe = `
import sys, os, json, ast
names = json.loads(sys.argv[1])
d = sys.argv[2]

def params_aliases(tree):
    """params 的别名：p = params or {} / p = dict(params) / p = params。
    2026-11-01 实锤：zip_chain_decode 这类薄封装把 params 改名后再取键，
    只认名字 'params' 会漏掉整整一类 skill 的契约。"""
    alias = {"params"}
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            t = node.targets[0]
            if not isinstance(t, ast.Name) or t.id in alias:
                continue
            names = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
            if names & alias:
                alias.add(t.id)
                changed = True
    return alias

def key_of(node, alias):
    """node 是 params.get('x') 或 params['x'] 时返回 'x'，否则 None。"""
    if isinstance(node, ast.Call):
        f = node.func
        if (isinstance(f, ast.Attribute) and f.attr == "get"
                and isinstance(f.value, ast.Name) and f.value.id in alias
                and node.args and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            return node.args[0].value
        return None
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in alias:
        sl = node.slice
        if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
            return sl.value
    return None

out = {}
for n in names:
    p = os.path.join(d, n + ".py")
    try:
        tree = ast.parse(open(p, encoding="utf-8", errors="replace").read())
    except Exception:
        continue
    alias = params_aliases(tree)
    keys = set()
    src_var = {}   # 局部变量名 -> 它来自哪个 params 键
    for node in ast.walk(tree):
        k = key_of(node, alias)
        if k:
            keys.add(k)
        # 注意：pk, ct = params.get("pk"), params.get("ct") 这种**元组赋值**的
        # value 是 Tuple 不是 Call，若只认 Assign(Call) 会漏掉一整批键。
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            t = node.targets[0]
            if isinstance(t, ast.Name):
                kk = key_of(node.value, alias)
                if kk:
                    src_var[t.id] = kk
    disp = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1 or not isinstance(node.ops[0], ast.Eq):
            continue
        for a, b in ((node.left, node.comparators[0]), (node.comparators[0], node.left)):
            if isinstance(a, ast.Name) and isinstance(b, ast.Constant) and isinstance(b.value, str):
                kk = src_var.get(a.id)
                if not kk:
                    continue
                lst = disp.setdefault(kk, [])
                if b.value not in lst:
                    lst.append(b.value)
    e = {}
    if keys:
        e["params"] = ",".join(sorted(keys))
    if disp:
        e["dispatch"] = disp
    if e:
        out[n] = e
print(json.dumps(out))
`
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx2, r.pythonPath, "-c", probe, string(namesJSON), r.skillsDir)
	cmd.Env = procenv.ChildEnv()
	out, err := cmd.Output()
	if err != nil {
		r.logger.Debug("skill 参数契约抽取失败（Desc 将只列名字）", zap.Error(err))
		return nil
	}
	var m map[string]skillContract
	if err := json.Unmarshal(out, &m); err != nil {
		r.logger.Debug("skill 参数契约解析失败", zap.Error(err))
		return nil
	}
	return m
}

// durFromEnv 读时长型环境变量（如 "180s"/"5m"），缺失或非法则用 def。
// 赛时需要按题型调超时（LLL 类 skill 单次可达 100s+，而 L2 批量扫必须短），
// 硬编码会让"要么批量扫拖死、要么单点调用够不着"二选一。
func durFromEnv(key string, def time.Duration) time.Duration {
	if v := osGetenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// osGetenv 包装：保留原 main 包内的调用形态（迁包后仍用它统一 TrimSpace 语义）
func osGetenv(key string) string {
	v, _ := os.LookupEnv(key)
	return strings.TrimSpace(v)
}

func osGetwd() (string, error)                 { return os.Getwd() }
func osStat(name string) (os.FileInfo, error)  { return os.Stat(name) }
func execLookPath(file string) (string, error) { return exec.LookPath(file) }

// collectStrings 递归收集 dict/list 里所有字符串值（跳过 __base64__ 包装）。
func collectStrings(v interface{}) []string {
	var out []string
	switch t := v.(type) {
	case string:
		out = append(out, t)
	case map[string]interface{}:
		for k, vv := range t {
			if k == "__base64__" {
				continue
			}
			out = append(out, collectStrings(vv)...)
		}
	case []interface{}:
		for _, vv := range t {
			out = append(out, collectStrings(vv)...)
		}
	}
	return out
}

// truncate 截断日志用文本，避免把 skill 的 base64 大输出灌进日志。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// totalSkills 返回 skillCatalog 总 skill 数（辅助 logger 输出）
func totalSkills(cat map[string][]string) int {
	n := 0
	for _, v := range cat {
		n += len(v)
	}
	return n
}

// checkDep pip show <name> 退出码 0 = 已装
func (r *Runner) checkDep(ctx context.Context, name string) bool {
	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx2, r.pythonPath, "-c",
		fmt.Sprintf("import importlib.util; print('OK' if importlib.util.find_spec(%q) else 'MISSING')", name))
	// 依赖探测本身不含模型输入，但它同样只解释器需要的变量才合理（少一份泄面）。
	cmd.Env = procenv.ChildEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "OK")
}

// TryCategoryBudget 对指定 category 依次跑"真跑"skill，
// 第一个返回 solved=True 且有 flag 的就用；budget 内没命中就放弃。
//
// 存在原因（2026-11-01 实测）：crypto 类挂 28 个 skill、单 skill 最多 6 个
// (文件×分派) 变体、每次子进程上限 30s ⇒ 无限预算下最坏可到 56 分钟/题。
// 原生产路径走的正是无限预算版本（本轮直接删掉，不留"忘了传预算"的口子），
// 等于赛时把单题时间预算整个吃光——属于"跑批里看不出、赛时致命"的类型。
func (r *Runner) TryCategoryBudget(ctx context.Context, category string, ch *ctfplatform.Challenge, budget time.Duration) ([]string, bool) {
	return r.tryCategory(ctx, category, ch, nil, budget)
}

// L2BudgetFromEnv 读 CTF_L2_BUDGET（如 "180s"），缺失/非法/<=0 用 def。
// 生产入口与跑批入口共用同一个真值源，避免"两边预算各写一份"再漂移。
func L2BudgetFromEnv(def time.Duration) time.Duration {
	if d := durFromEnv("CTF_L2_BUDGET", 0); d > 0 {
		return d
	}
	return def
}

// TryCategoryLocal 与 TryCategoryBudget 同语义，但额外把**本地附件路径**注入 params["path"]。
//
// 存在原因（2026-11-01）：L2 原来只认 ch.AttachmentURLs（平台给的下载 URL），
// 离线跑批的附件是本地文件、没有 URL ⇒ L2 永远拿不到 path ⇒ 所有"吃文件"的
// skill 在跑批里一律等于没接上（与 40/40 附件静默阉割同型）。
//
// budget>0 时限制**整类**总耗时；<=0 表示不限（跑批里留作显式诊断口子，
// 生产路径不得使用——cmd/runner 走 TryCategoryBudget + CTF_L2_BUDGET）。
func (r *Runner) TryCategoryLocal(ctx context.Context, category string, ch *ctfplatform.Challenge, localFiles []string, budget time.Duration) ([]string, bool) {
	return r.tryCategory(ctx, category, ch, localFiles, budget)
}

func (r *Runner) tryCategory(ctx context.Context, category string, ch *ctfplatform.Challenge, localFiles []string, budget time.Duration) ([]string, bool) {
	skills, ok := r.skillCatalog[category]
	if !ok || len(skills) == 0 {
		return nil, false
	}
	// bases：每轮"基础参数"。有本地附件时**每个文件各算一个基础**——
	// 2026-11-01 实锤：只取排序第一个文件时，mhk2 拿到的是 MHK2.sage 而不是
	// output.txt，json 解析必然失败，skill 明明能解也永远命中不了。
	var bases []map[string]any
	if len(localFiles) == 0 {
		bases = []map[string]any{nil}
	} else {
		for i, f := range localFiles {
			if i >= maxPathVariants {
				break
			}
			bases = append(bases, map[string]any{
				"path":  f,
				"files": localFiles,
				"dir":   filepath.Dir(f),
			})
		}
	}
	var deadline time.Time
	if budget > 0 {
		deadline = time.Now().Add(budget)
	}

	r.logger.Debug("尝试 Python skill 求解",
		zap.String("category", category),
		zap.String("challenge", ch.Title),
		zap.Strings("skills", skills))

	for _, skillName := range skills {
		if !deadline.IsZero() && time.Now().After(deadline) {
			r.logger.Warn("L2 超出时间预算，剩余 skill 未尝试",
				zap.String("category", category),
				zap.Duration("budget", budget),
				zap.String("at", skillName))
			break
		}
		// 依赖门控（2026-10-25 扩：加 NeedCrypto，覆盖 crypto_* skill 大部分）
		switch skillName {
		case "reverse_angr_solver":
			if !r.hasAngr {
				continue
			}
		case "pwn_ret2dlresolve", "pwn_nogdb_flow", "pwn_sandbox_escape":
			// pwn_exploit_flow 故意不在此列——它不 import pwntools（Advisor 复核我扫描结果：NeedPwn=False）
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

		var variants []map[string]any
		for _, b := range bases {
			variants = append(variants, r.paramVariants(skillName, b)...)
			if len(variants) >= maxVariantsPerSkill {
				break
			}
		}
		if len(variants) > maxVariantsPerSkill {
			variants = variants[:maxVariantsPerSkill]
		}
		for _, params := range variants {
			if !deadline.IsZero() && time.Now().After(deadline) {
				r.logger.Warn("L2 超出时间预算，剩余 skill/分派未尝试",
					zap.String("category", category),
					zap.Duration("budget", budget),
					zap.String("at", skillName))
				return nil, false
			}
			// 单点上限 = min(剩余预算, l2Timeout)。默认 120s 而不是 30s：
			// LLL 类 skill（mhk2_decrypt 实测 99.4s）在 30s 下必然被掐死，
			// 日志只写 "L2-MISS"，看起来像"skill 解不了"，实则超时。
			limit := r.l2Timeout
			if limit <= 0 {
				limit = r.timeout
			}
			if !deadline.IsZero() {
				if rem := time.Until(deadline); rem < limit {
					limit = rem
				}
			}
			// 诊断可见性：L2 是"静默遍历"，出问题时（跑了但全 miss）
			// 只能靠这条日志看出到底给 skill 喂了什么参数。
			tTry := time.Now()
			flags, ok := r.runSkillWithLimit(ctx, skillName, ch, params, limit)
			r.logger.Debug("L2 试 skill",
				zap.String("skill", skillName),
				zap.String("path", fmt.Sprint(params["path"])),
				zap.String("kind", fmt.Sprint(params["kind"])),
				zap.Bool("got", ok && len(flags) > 0),
				zap.Duration("took", time.Since(tTry)))
			if ok && len(flags) > 0 {
				return flags, true
			}
		}
	}
	return nil, false
}

// maxPathVariants 限制"每个 skill 试几个本地附件"；maxVariantsPerSkill 限制
// (文件 × 分派) 的总展开数。二者相乘决定了单 skill 最坏耗时上限，
// 不设界会让 28 个 crypto skill 的 L2 扫描变成小时级。
const (
	maxPathVariants     = 3
	maxVariantsPerSkill = 6
)

// maxDispatchVariants 限制单个 skill 的分派展开数：15 个 skill 用 kind 分派，
// 若每个都展开 3 个值、再乘以 30s 超时，预算会被瞬间吃光。
const maxDispatchVariants = 4

// paramVariants 在基础参数上叠加**分派候选值**（如 kind=mhk2_decrypt / recover_key）。
//
// 为什么需要：L2 是确定性路由，它没法知道"这道 MHK2 该用 mhk2_decrypt 还是
// recover_key"——这是语义判断。2026-11-01 实测：只注入 path 时 knapsack 在
// 2.4s 内返回 "unknown kind" 就算失败，L2 等于没接上。源码里的
// `if kind == "mhk2_decrypt"` 分支就是答案，按它逐个试即可。
//
// 调用方显式给了该键（模型/上层指定）→ 不再叠加猜测，尊重显式值。
// 没有分派信息（或未探测到）→ 只返回基础参数本身，行为与改造前一致。
func (r *Runner) paramVariants(skillName string, base map[string]any) []map[string]any {
	out := []map[string]any{base}
	c, ok := r.skillContracts[skillName]
	if !ok || len(c.Dispatch) == 0 {
		return out
	}
	keys := make([]string, 0, len(c.Dispatch))
	for k := range c.Dispatch {
		keys = append(keys, k)
	}
	sort.Strings(keys) // 固定顺序：多个分派键时只展开第一个，避免笛卡尔积爆炸
	dk := keys[0]
	if _, exists := base[dk]; exists {
		return out
	}
	for _, dv := range c.Dispatch[dk] {
		if len(out) >= maxDispatchVariants {
			break
		}
		v := make(map[string]any, len(base)+1)
		for k, vv := range base {
			v[k] = vv
		}
		v[dk] = dv
		out = append(out, v)
	}
	return out
}

// RunSkill subprocess 调单个 Python skill，返回 (flag candidates, 是否成功)
// 导出为 RunSkill：供 internal/runnerl3.SkillRunner 接口解耦（execute_python 工具依赖）。
// 2026-10-25 参数契约增强：Runner 之前只传 4 字段（name/category/description/attachment_urls），
// 但 skill 通常需要 text/path/key。现在：
//
//	① 从 description regex 提取 text（密文）和 key（密钥）
//	② attachment_urls 非空 → 下载第一个附件到临时文件传 path
func (r *Runner) RunSkill(ctx context.Context, skillName string, ch *ctfplatform.Challenge) ([]string, bool) {
	return r.runSkillWith(ctx, skillName, ch, nil)
}

// runSkillWith 是 RunSkill 的实现体。extra 在**所有**推导之后覆盖：本地附件 path
// 必须压过"从 description 正则猜出来的 text/key"，否则注入等于没注入。
func (r *Runner) runSkillWith(ctx context.Context, skillName string, ch *ctfplatform.Challenge, extra map[string]any) ([]string, bool) {
	return r.runSkillWithLimit(ctx, skillName, ch, extra, r.timeout)
}

// runSkillWithLimit 与 runSkillWith 同体，但显式给单次子进程上限。
// L2 需要它：整类预算是硬的，单点上限必须能在预算耗尽时被裁到剩余量，
// 否则最后一个 skill 会带着 120s 上限冲出预算（预算形同虚设）。
func (r *Runner) runSkillWithLimit(ctx context.Context, skillName string, ch *ctfplatform.Challenge, extra map[string]any, limit time.Duration) ([]string, bool) {
	params := r.buildSkillParams(ctx, ch)

	// 从 description 提取 text（密文）——匹配 "密文: xxx" / "cipher: xxx" / "text=xxx" 等常见格式
	if text := extractSkillText(ch.Description); text != "" {
		params["text"] = text
	}
	// 从 description 提取 key（Vigenère 等需要密钥）
	if key := extractSkillKey(ch.Description); key != "" {
		params["key"] = key
	}

	// 附件：如果有 URL，下载第一个到临时文件并传 path
	if len(ch.AttachmentURLs) > 0 {
		params["attachment_urls"] = ch.AttachmentURLs
		if localPath, err := r.downloadAttachment(ctx, ch.AttachmentURLs[0]); err == nil {
			params["path"] = localPath
		} else {
			r.logger.Debug("附件下载失败，跳过 path 参数", zap.String("url", ch.AttachmentURLs[0]), zap.Error(err))
		}
	}

	// extra 必须在这里合并 —— 在 exec 之前！2026-11-01 自伤事故：这段原被插到
	// "解析 JSON 返回值"之前，而那行在子进程执行**之后**，于是 L2 注入的
	// path/kind 从未真正传给 skill：日志显示 kind=mhk2_decrypt，skill 实际收到空
	// kind 并返回 "unknown kind"。现象极像"skill 不解决问题"，实则参数没送到。
	for k, v := range extra {
		params[k] = v
	}

	out, ok := r.execSkillSubprocess(ctx, skillName, params, limit)
	if !ok {
		// 静默失败是 L2 最难查的地方：skill 自己 catch 住异常返回
		// {"ok": false, "error": ...} 时退出码是 0，外层看不到任何信号。
		r.logger.Debug("skill 子进程未成功", zap.String("skill", skillName), zap.String("raw", truncate(out, 400)))
		return nil, false
	}

	// 解析 JSON 返回值
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		// 有些 skill 可能返回 list 或直接字符串
		r.logger.Debug("skill 返回值非 dict", zap.String("skill", skillName), zap.String("raw", out))
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
	okFlag, _ := result["ok"].(bool)
	if solved || okFlag {
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

	// 2026-11-01 实锤：crypto_knapsack_mhk 把解出的明文放在 "plaintext" 字段，
	// 而这里只认 flag/flags ⇒ skill 明明解出来了却被判"未命中"。
	// 兜底：只要 skill 自报成功（ok/solved），就从**所有**字符串值里按形态挑
	// flag（plaintext / text / decoded / data 这些键都可能装答案）。
	// 判分侧仍走 sha256 精确比对，这里放宽不会制造"假解出"。
	if solved || okFlag {
		if cands := ctfplatform.FilterFlagCandidates(collectStrings(result)); len(cands) > 0 {
			r.logger.Debug("skill 命中（flag 在非 flag 字段）",
				zap.String("skill", skillName), zap.Strings("flags", cands))
			return cands, true
		}
	}
	keys := make([]string, 0, len(result))
	for k := range result {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	r.logger.Debug("skill 返回但无 flag 字段",
		zap.String("skill", skillName),
		zap.Strings("keys", keys),
		zap.String("raw", truncate(out, 300)))

	return nil, false
}

// buildSkillParams 从 Challenge 组装 skill 入参（RunSkill / RunSkillRich 共用）。
// 2026-10-25 参数契约：Runner 之前只传 4 字段（name/category/description/attachment_urls），
// 但 skill 通常需要 text/path/key。现在：
//
//	① 从 description regex 提取 text（密文）和 key（密钥）
//	② attachment_urls 非空 → 下载第一个附件到临时文件传 path
func (r *Runner) buildSkillParams(ctx context.Context, ch *ctfplatform.Challenge) map[string]interface{} {
	params := map[string]interface{}{
		"name":        ch.Title,
		"category":    ch.Category,
		"description": ch.Description,
	}

	// 从 description 提取 text（密文）——匹配 "密文: xxx" / "cipher: xxx" / "text=xxx" 等常见格式
	if text := extractSkillText(ch.Description); text != "" {
		params["text"] = text
	}
	// 从 description 提取 key（Vigenère 等需要密钥）
	if key := extractSkillKey(ch.Description); key != "" {
		params["key"] = key
	}

	// 附件：如果有 URL，下载第一个到临时文件并传 path
	if len(ch.AttachmentURLs) > 0 {
		params["attachment_urls"] = ch.AttachmentURLs
		if localPath, err := r.downloadAttachment(ctx, ch.AttachmentURLs[0]); err == nil {
			params["path"] = localPath
		} else {
			r.logger.Debug("附件下载失败，跳过 path 参数", zap.String("url", ch.AttachmentURLs[0]), zap.Error(err))
		}
	}
	return params
}

// execSkillSubprocess 以子进程跑单个 skill 模块，返回 (原始输出文本, 是否成功)。
// RunSkill 与 RunSkillRich 共用同一调用契约：skillsDir 进 sys.path → import 模块 →
// run(json params) → print(json.dumps(result))；bytes 值递归 sanitize 成 base64 dict。
// 输出为 stdout/stderr 合并文本，解析方式由调用方决定（flag 提取或原样交 LLM）。
//
// skillNameIdentRe 合法 Python 标识符 —— skill 名会被 fmt.Sprintf 拼进下面
// execSkillSubprocess 的源码模板（`import %s as s`），非法字符即代码注入。
var skillNameIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (r *Runner) execSkillSubprocess(ctx context.Context, skillName string, params map[string]interface{}, limit time.Duration) (string, bool) {
	// 纵深防御（2026-11-01）：上层 internal/runnerl3 已经校验过 skill_name，
	// 但这里是**真正拼源码**的地方 —— 谁调用都得在同一处被拦住（L2 编排、
	// 未来新增调用方都不会漏）。非法名一律不执行，返回失败而非报错文本，
	// 避免任何模型输入进入 Python 源码。
	if !skillNameIdentRe.MatchString(skillName) {
		r.logger.Warn("skill 名不是合法标识符（疑似代码注入），拒绝执行",
			zap.String("skill", skillName))
		return "", false
	}

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		r.logger.Warn("skill 参数序列化失败", zap.String("skill", skillName), zap.Error(err))
		return "", false
	}

	// python -c 脚本：递归 sanitize 所有 bytes 值为 base64 包装 dict（防止 json.dumps 崩溃）
	// 2026-10-25 嵌套 bytes 修复：之前只处理顶层 isinstance(_r, bytes)，dict/list 内部嵌套的 bytes 仍会让 json.dumps 崩
	// 递归 walk 所有 dict/list 元素，任何 bytes 值都 base64 编码成 {"__base64__": "...", "__orig__": "bytes"}
	const scriptTpl = `
import sys, json, base64, os, asyncio
sys.path.insert(0, %q)
sys.path.insert(0, os.path.dirname(%q))
def _sanitize(obj):
    if isinstance(obj, bytes):
        return {"__base64__": base64.b64encode(obj).decode(), "__orig__": "bytes"}
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize(item) for item in obj]
    return obj
import %s as s
try:
    _r = s.run(json.loads(sys.argv[1]))
    if asyncio.iscoroutine(_r):
        _r = asyncio.run(_r)
    _r = _sanitize(_r)
    print(json.dumps(_r))
except Exception as _e:
    print(json.dumps({"__error__": str(_e)}), file=sys.stderr)
    sys.exit(1)
`
	script := fmt.Sprintf(scriptTpl, r.skillsDir, r.skillsDir, skillName)

	// limit<=0 兜底：Runner 可能被逐字段构造（测试、未来新增入口），漏设 richTimeout
	// 会让 WithTimeout(0) 立刻到期 —— 表现为"skill 静默失败、输出为空"，极难排查。
	if limit <= 0 {
		limit = r.timeout
	}
	if limit <= 0 {
		limit = 30 * time.Second
	}
	ctx2, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	cmd := exec.CommandContext(ctx2, r.pythonPath, "-c", script, string(paramsJSON))
	// 环境失敏（2026-11-01 09:04 真机事故）：skill 子进程是模型可驱动的
	// （params 直接来自模型），继承整份进程环境等于把 API key / 平台令牌 /
	// ssh-agent 一起交出去 —— 模型 `print(os.environ)` 就能全部收走。
	// 见 internal/procenv 与 py_session.go 同一处修法。
	cmd.Env = procenv.ChildEnv()
	out, err := cmd.CombinedOutput()

	if ctx2.Err() == context.DeadlineExceeded {
		r.logger.Warn("skill 超时", zap.String("skill", skillName), zap.Duration("timeout", limit))
		return "", false
	}
	if err != nil {
		r.logger.Debug("skill 执行失败",
			zap.String("skill", skillName),
			zap.Error(err),
			zap.String("stderr", string(out)))
		return "", false
	}
	return string(out), true
}

// RunSkillRich 是 internal/runnerl3.RichSkillRunner 的实现（P0-1 ctf_sage 模板接入，2026-10-25）。
// 与 RunSkill 的两点区别：
//
//	① extra（LLM 经 execute_python 的 params 字段传入的数学参数：n/e/c/f_coeffs/sigs…）
//	   并入 skill params，优先级高于 description 正则提取值——数学模板要精确参数，不要猜；
//	② 返回完整结果文本而非只提取 flag——数学模板的产出是中间量（小根/私钥/明文），
//	   flag 契约会把它们丢掉；LLM 需要看到原始结果才能决定下一步（如解密得 flag）。
func (r *Runner) RunSkillRich(ctx context.Context, skillName string, ch *ctfplatform.Challenge, extra map[string]any) (string, bool) {
	params := r.buildSkillParams(ctx, ch)
	for k, v := range extra {
		params[k] = v
	}
	return r.execSkillSubprocess(ctx, skillName, params, r.richTimeout)
}

// extractSkillText 从 Challenge.Description 中提取密文文本。
// 匹配常见格式："密文: xxx" / "cipher: xxx" / "text=xxx" / "密文=xxx" / "Ciphertext: xxx" / "encoded: xxx"
func extractSkillText(desc string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:密文|cipher|ciphertext|encrypted|编码|encoded|text)\s*[:=]\s*[` + "`" + `"]?([A-Za-z0-9+/={}._\-;,\s]{4,})[` + "`" + `"]?`),
		regexp.MustCompile(`(?i)(?:密文|cipher|encoded)\s+is\s+[` + "`" + `"]?([A-Za-z0-9+/={}._\-;,\s]{4,})[` + "`" + `"]?`),
	}
	for _, p := range patterns {
		if m := p.FindStringSubmatch(desc); len(m) > 1 {
			return strings.TrimSpace(m[1])
		}
	}
	return ""
}

// extractSkillKey 从 Challenge.Description 中提取密钥（Vigenère/Playfair 等需要）
// 匹配："key: SECRET" / "密钥=SECRET" / "key SECRET"（空格也接受，因为 CTF 题描述常省冒号）
func extractSkillKey(desc string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:密钥|key|secret)\s*[:=\s]\s*[` + "`" + `"]?([A-Za-z0-9_\-]{2,})[` + "`" + `"]?`),
	}
	for _, p := range patterns {
		if m := p.FindStringSubmatch(desc); len(m) > 1 {
			return strings.TrimSpace(m[1])
		}
	}
	return ""
}

// downloadAttachment 从 URL 下载附件到系统临时目录，返回文件路径。
// 超时 30s，最大 50MB（与 Runner LLM read_attachment 工具一致）
func (r *Runner) downloadAttachment(ctx context.Context, url string) (string, error) {
	httpClient := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// 50MB 上限
	const maxSize = 50 * 1024 * 1024
	if resp.ContentLength > maxSize {
		return "", fmt.Errorf("附件太大: %d bytes (上限 %d)", resp.ContentLength, maxSize)
	}

	// 写临时文件
	tmp, err := os.CreateTemp("", "runner-attach-*")
	if err != nil {
		return "", err
	}
	defer tmp.Close()

	// 带大小限制的复制器
	limited := io.LimitReader(resp.Body, maxSize+1)
	if _, err := io.Copy(tmp, limited); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
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
//
//	① **死候选**：归档副本排在它前面且恒存在，那条永远不会命中；
//	② **注释与代码曾经顺序相反**（注释说源仓第 3、归档第 4，代码正好颠倒），
//	   留着只会继续误导后来人；
//	③ 它是「西湖论剑尚未彻底并入」在运行链上的**唯一残留**——删掉之后，
//	   "把 E:\Program\西湖论剑 整个删掉、本项目功能不受影响"才成为可验证的事实。
//
// 不变量由 bridge_test.go::TestCandidateSkillDirsAreRepoLocal 锁住：
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
	// 用 filepath.Join 而非硬编码反斜杠：Runner 二进制最终 scp 到 Linux 服务器运行，
	// 反斜杠在 Linux 上会被当成普通字符，导致候选路径根本不存在、Layer 2 静默失效。
	// 2026-10-25 实测：本机(Windows)测试能过，但服务器(Linux) findSkillsDir 恒返回空。
	return []string{
		filepath.Join(cwd, "internal", "ctfplatform", "pyskills"),
		filepath.Join(cwd, "skills", "python"),
		filepath.Join(cwd, "CTF-Agent_融合", "ctf_agent", "skills"),
	}
}
