// Package ctfplatform 提供确定性求解器注册表。
//
// 设计：每个求解器实现 SolverFunc 签名，通过 init() 自动注册到全局注册表。
// Presolve 层遍历注册表并发执行，支持按优先级排序。
// 新增求解器只需：1. 实现 SolverFunc 2. 在 init() 注册 3. 不改主循环。
package ctfplatform

import (
	"context"
	"sort"
	"sync"

	"go.uber.org/zap"
)

// SolverCategory 求解器分类（按题目类型）。
type SolverCategory string

const (
	CategoryAll     SolverCategory = "all"      // 全题型通用（如 flag 扫描）
	CategoryCryptoS SolverCategory = "crypto"   // 密码学
	CategoryMiscS   SolverCategory = "misc"     // 杂项
	CategoryWebS    SolverCategory = "web"      // Web 安全
	CategoryRevS    SolverCategory = "reverse"  // 逆向工程
	CategoryPwnS    SolverCategory = "pwn"      // 二进制漏洞利用
)

// SolverFunc 求解器函数签名：输入题目描述+附件，返回候选 flag 列表。
// 无命中返回 nil。注意：复用 poller.go 中已定义的 SolverFunc，
// 但注册表使用更通用的 ContextSolverFunc。
type ContextSolverFunc func(ctx context.Context, text string, attachments map[string]string) []string

// SolverEntry 求解器注册条目。
type SolverEntry struct {
	Name       string         // 求解器名（如 "flag_scan"、"rsa_fermat"）
	Category   SolverCategory // 分类（用于按题型过滤）
	Priority   int            // 优先级（越小越先执行，0=最高）
	Solver     ContextSolverFunc     // 求解函数
	Enabled    bool           // 是否启用
}

// solverRegistry 全局求解器注册表。
var solverRegistry = struct {
	mu      sync.RWMutex
	entries []SolverEntry
}{}

// RegisterSolver 注册一个确定性求解器到全局注册表。
// 应在 init() 中调用。
func RegisterSolver(entry SolverEntry) {
	solverRegistry.mu.Lock()
	defer solverRegistry.mu.Unlock()
	if entry.Priority == 0 {
		entry.Priority = 100 // 默认优先级
	}
	entry.Enabled = true
	solverRegistry.entries = append(solverRegistry.entries, entry)
}

// GetSolvers 获取所有已注册的求解器（按优先级排序）。
func GetSolvers() []SolverEntry {
	solverRegistry.mu.RLock()
	defer solverRegistry.mu.RUnlock()
	result := make([]SolverEntry, len(solverRegistry.entries))
	copy(result, solverRegistry.entries)
	sort.Slice(result, func(i, j int) bool {
		return result[i].Priority < result[j].Priority
	})
	return result
}

// GetSolversByCategory 按分类筛选求解器。
func GetSolversByCategory(cat SolverCategory) []SolverEntry {
	all := GetSolvers()
	var filtered []SolverEntry
	for _, s := range all {
		if s.Category == CategoryAll || s.Category == cat {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// GetSolverCount 返回已注册求解器数量。
func GetSolverCount() int {
	solverRegistry.mu.RLock()
	defer solverRegistry.mu.RUnlock()
	return len(solverRegistry.entries)
}

// ── 内置求解器自动注册 ──────────────────────────────────

func init() {
	// 全题型通用（最高优先级）
	RegisterSolver(SolverEntry{Name: "flag_scan", Category: CategoryAll, Priority: 10, Solver: solveFlagScan})
	RegisterSolver(SolverEntry{Name: "base64_multilayer", Category: CategoryAll, Priority: 20, Solver: solveBase64Multilayer})

	// 密码学
	RegisterSolver(SolverEntry{Name: "caesar", Category: CategoryCryptoS, Priority: 30, Solver: solveCaesar})
	RegisterSolver(SolverEntry{Name: "xor_single", Category: CategoryCryptoS, Priority: 31, Solver: solveXOR})
	RegisterSolver(SolverEntry{Name: "hash_crack", Category: CategoryCryptoS, Priority: 32, Solver: solveHashCrack})
	RegisterSolver(SolverEntry{Name: "rsa_template", Category: CategoryCryptoS, Priority: 40, Solver: solveRSATemplate})
	RegisterSolver(SolverEntry{Name: "legendre_phi", Category: CategoryCryptoS, Priority: 41, Solver: solveLegendrePhi})
	RegisterSolver(SolverEntry{Name: "modinv_factor", Category: CategoryCryptoS, Priority: 42, Solver: solveModInvFactor})
	RegisterSolver(SolverEntry{Name: "aes_ecb", Category: CategoryCryptoS, Priority: 50, Solver: solveAESECB})
	RegisterSolver(SolverEntry{Name: "lattice", Category: CategoryCryptoS, Priority: 51, Solver: solveLattice})
	RegisterSolver(SolverEntry{Name: "keyboard_path", Category: CategoryCryptoS, Priority: 52, Solver: solveKeyboardPath})
	RegisterSolver(SolverEntry{Name: "high_exponent_variant", Category: CategoryCryptoS, Priority: 53, Solver: solveHighExponentVariant})
	RegisterSolver(SolverEntry{Name: "common_modulus", Category: CategoryCryptoS, Priority: 54, Solver: solveCommonModulus})

	// 杂项
	RegisterSolver(SolverEntry{Name: "morse", Category: CategoryMiscS, Priority: 60, Solver: solveMorse})
	RegisterSolver(SolverEntry{Name: "vigenere", Category: CategoryMiscS, Priority: 61, Solver: solveVigenere})
	RegisterSolver(SolverEntry{Name: "zip_fake_enc", Category: CategoryMiscS, Priority: 62, Solver: solveZIPFake})
	RegisterSolver(SolverEntry{Name: "stego_detect", Category: CategoryMiscS, Priority: 70, Solver: solveStegoDetect})
	RegisterSolver(SolverEntry{Name: "traffic_analysis", Category: CategoryMiscS, Priority: 71, Solver: solveTrafficAnalysis})
	RegisterSolver(SolverEntry{Name: "disk_forensics", Category: CategoryMiscS, Priority: 72, Solver: solveDiskForensics})
	RegisterSolver(SolverEntry{Name: "zip_chain", Category: CategoryMiscS, Priority: 73, Solver: solveZipChain})

	// Web 安全
	RegisterSolver(SolverEntry{Name: "web_source_audit", Category: CategoryWebS, Priority: 80, Solver: solveWebSourceAudit})
	RegisterSolver(SolverEntry{Name: "ssti", Category: CategoryWebS, Priority: 81, Solver: solveSSTI})
	RegisterSolver(SolverEntry{Name: "sqli", Category: CategoryWebS, Priority: 82, Solver: solveSQLi})
	RegisterSolver(SolverEntry{Name: "ssrf", Category: CategoryWebS, Priority: 83, Solver: solveSSRF})
	RegisterSolver(SolverEntry{Name: "xxe", Category: CategoryWebS, Priority: 84, Solver: solveXXE})
	RegisterSolver(SolverEntry{Name: "jwt", Category: CategoryWebS, Priority: 85, Solver: solveJWT})
	RegisterSolver(SolverEntry{Name: "race_condition", Category: CategoryWebS, Priority: 86, Solver: solveRaceCondition})

	// 逆向工程
	RegisterSolver(SolverEntry{Name: "strings_flag", Category: CategoryRevS, Priority: 90, Solver: solveStringsFlag})
	RegisterSolver(SolverEntry{Name: "go_binary", Category: CategoryRevS, Priority: 91, Solver: solveGoBinary})
	RegisterSolver(SolverEntry{Name: "hardcoded_secrets", Category: CategoryRevS, Priority: 92, Solver: solveHardcodedSecrets})
	RegisterSolver(SolverEntry{Name: "reverse_keywords", Category: CategoryRevS, Priority: 93, Solver: solveReverseKeywords})

	// 二进制漏洞利用
	RegisterSolver(SolverEntry{Name: "pwn_libc_fingerprint", Category: CategoryPwnS, Priority: 100, Solver: solvePwnLibcFingerprint})
	RegisterSolver(SolverEntry{Name: "pwn_exploit_pattern", Category: CategoryPwnS, Priority: 101, Solver: solvePwnExploitPattern})
	RegisterSolver(SolverEntry{Name: "pwn_advanced", Category: CategoryPwnS, Priority: 102, Solver: solvePwnAdvanced})

	// 符号执行/动态分析/固件分析（P5 补全）
	RegisterSolver(SolverEntry{Name: "symbolic_execution", Category: CategoryRevS, Priority: 94, Solver: solveSymbolicExecution})
	RegisterSolver(SolverEntry{Name: "dynamic_analysis", Category: CategoryAll, Priority: 95, Solver: solveDynamicAnalysis})
	RegisterSolver(SolverEntry{Name: "firmware_analysis", Category: CategoryRevS, Priority: 96, Solver: solveFirmwareAnalysis})

	// 密码学高级 + CTF 实战高频（P6 批次）
	RegisterSolver(SolverEntry{Name: "rsa_wiener", Category: CategoryCryptoS, Priority: 43, Solver: solveRSAWiener})
	RegisterSolver(SolverEntry{Name: "pohlig_hellman", Category: CategoryCryptoS, Priority: 44, Solver: solvePohligHellman})
	RegisterSolver(SolverEntry{Name: "padding_oracle", Category: CategoryCryptoS, Priority: 45, Solver: solvePaddingOracle})
	RegisterSolver(SolverEntry{Name: "misc_frequency", Category: CategoryMiscS, Priority: 63, Solver: solveMiscFrequency})
	RegisterSolver(SolverEntry{Name: "template_injection", Category: CategoryWebS, Priority: 87, Solver: solveWebTemplateInjection})
	RegisterSolver(SolverEntry{Name: "blockchain_ctf", Category: CategoryMiscS, Priority: 74, Solver: solveBlockchainCTF})
	RegisterSolver(SolverEntry{Name: "ml_security", Category: CategoryMiscS, Priority: 75, Solver: solveMLSecurity})

	// misc 高级（P7 批次）
	RegisterSolver(SolverEntry{Name: "brainfuck", Category: CategoryMiscS, Priority: 64, Solver: solveBrainfuck})
	RegisterSolver(SolverEntry{Name: "ook", Category: CategoryMiscS, Priority: 65, Solver: solveOok})
	RegisterSolver(SolverEntry{Name: "rail_fence_variant", Category: CategoryCryptoS, Priority: 66, Solver: solveRailFenceVariant})
	RegisterSolver(SolverEntry{Name: "vigenere_auto_key", Category: CategoryCryptoS, Priority: 67, Solver: solveVigenereAutoKey})

	// crypto 高级（P7 批次）
	RegisterSolver(SolverEntry{Name: "ecdsa_nonce_reuse", Category: CategoryCryptoS, Priority: 46, Solver: solveECDSANonceReuse})
	RegisterSolver(SolverEntry{Name: "rsa_broadcast", Category: CategoryCryptoS, Priority: 47, Solver: solveRSABroadcast})
	RegisterSolver(SolverEntry{Name: "xor_multi_byte", Category: CategoryCryptoS, Priority: 33, Solver: solveXORMultiByte})

	// web 高级（P7 批次）
	RegisterSolver(SolverEntry{Name: "prototype_pollution", Category: CategoryWebS, Priority: 88, Solver: solvePrototypePollution})
	RegisterSolver(SolverEntry{Name: "graphql_batch", Category: CategoryWebS, Priority: 89, Solver: solveGraphQLBatch})
	RegisterSolver(SolverEntry{Name: "http_smuggling", Category: CategoryWebS, Priority: 90, Solver: solveHTTPRequestSmuggling})

	// P8 批次：crypto 深水区
	RegisterSolver(SolverEntry{Name: "elliptic_curve", Category: CategoryCryptoS, Priority: 48, Solver: solveEllipticCurve})
	RegisterSolver(SolverEntry{Name: "lattice_lll", Category: CategoryCryptoS, Priority: 49, Solver: solveLatticeLLL})
	RegisterSolver(SolverEntry{Name: "polynomial_discrete_log", Category: CategoryCryptoS, Priority: 50, Solver: solvePolynomialDiscreteLog})

	// P8 批次：misc 深水区
	RegisterSolver(SolverEntry{Name: "dna_coding", Category: CategoryMiscS, Priority: 76, Solver: solveDNACoding})
	RegisterSolver(SolverEntry{Name: "braille", Category: CategoryMiscS, Priority: 77, Solver: solveBraille})
	RegisterSolver(SolverEntry{Name: "barcode", Category: CategoryMiscS, Priority: 78, Solver: solveBarcode})

	// P8 批次：web 深水区
	RegisterSolver(SolverEntry{Name: "websocket_hijack", Category: CategoryWebS, Priority: 91, Solver: solveWebSocketHijack})
	RegisterSolver(SolverEntry{Name: "pp_variant", Category: CategoryWebS, Priority: 92, Solver: solvePrototypePollutionVariant})

	// P8 批次：reverse 深水区
	RegisterSolver(SolverEntry{Name: "obfuscation_detect", Category: CategoryRevS, Priority: 97, Solver: solveObfuscationDetection})
	RegisterSolver(SolverEntry{Name: "emulator_detect", Category: CategoryRevS, Priority: 98, Solver: solveEmulatorDetection})
	RegisterSolver(SolverEntry{Name: "code_virtualization", Category: CategoryRevS, Priority: 99, Solver: solveCodeVirtualization})
}

// ── 求解器函数适配器（调用现有 presolve.go 的实现） ──────

func solveFlagScan(ctx context.Context, text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	return scanFlags(fullText)
}

func solveBase64Multilayer(ctx context.Context, text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	return tryBase64Multilayer(fullText)
}

func solveCaesar(ctx context.Context, text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	if len(fullText) < 500 {
		return tryCaesar(fullText)
	}
	return nil
}

func solveXOR(ctx context.Context, text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	return tryXOR(fullText)
}

func solveHashCrack(ctx context.Context, text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	return tryHashCrack(fullText)
}

func solveRSATemplate(ctx context.Context, text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	return tryRSATemplate(fullText)
}

func solveLegendrePhi(ctx context.Context, text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	return tryLegendrePhi(fullText)
}

func solveModInvFactor(ctx context.Context, text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	return tryModInvFactor(fullText)
}

func solveAESECB(ctx context.Context, text string, attachments map[string]string) []string {
	return tryAESECB(text, attachments)
}

func solveLattice(ctx context.Context, text string, attachments map[string]string) []string {
	return tryLattice(text, attachments)
}

func solveKeyboardPath(ctx context.Context, text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	return tryKeyboardPath(fullText)
}

func solveHighExponentVariant(ctx context.Context, text string, attachments map[string]string) []string {
	return tryHighExponentVariant(text, attachments)
}

func solveCommonModulus(ctx context.Context, text string, attachments map[string]string) []string {
	return tryCommonModulus(text, attachments)
}

func solveMorse(ctx context.Context, text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	return tryMorse(fullText)
}

func solveVigenere(ctx context.Context, text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	return tryVigenere(fullText)
}

func solveZIPFake(ctx context.Context, text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	return tryZIPFakeEncryption(fullText)
}

func solveStegoDetect(ctx context.Context, text string, attachments map[string]string) []string {
	return tryStegoDetect(text, attachments)
}

func solveTrafficAnalysis(ctx context.Context, text string, attachments map[string]string) []string {
	return tryTrafficAnalysis(text, attachments)
}

func solveDiskForensics(ctx context.Context, text string, attachments map[string]string) []string {
	return tryDiskForensics(text, attachments)
}

func solveZipChain(ctx context.Context, text string, attachments map[string]string) []string {
	return tryZipChain(text, attachments)
}

func solveWebSourceAudit(ctx context.Context, text string, attachments map[string]string) []string {
	return tryWebSourceAudit(text, attachments)
}

func solveSSTI(ctx context.Context, text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	return trySSTI(fullText)
}

func solveSQLi(ctx context.Context, text string, attachments map[string]string) []string {
	return trySQLi(text, attachments)
}

func solveSSRF(ctx context.Context, text string, attachments map[string]string) []string {
	return trySSRF(text, attachments)
}

func solveXXE(ctx context.Context, text string, attachments map[string]string) []string {
	return tryXXE(text, attachments)
}

func solveJWT(ctx context.Context, text string, attachments map[string]string) []string {
	return tryJWT(text, attachments)
}

func solveRaceCondition(ctx context.Context, text string, attachments map[string]string) []string {
	return tryRaceCondition(text, attachments)
}

func solveStringsFlag(ctx context.Context, text string, attachments map[string]string) []string {
	return tryStringsFlagScan(text, attachments)
}

func solveGoBinary(ctx context.Context, text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	return tryGoBinaryStrings(fullText)
}

func solveHardcodedSecrets(ctx context.Context, text string, attachments map[string]string) []string {
	return tryHardcodedSecrets(text, attachments)
}

func solveReverseKeywords(ctx context.Context, text string, attachments map[string]string) []string {
	return tryReverseKeywords(text, attachments)
}

func solvePwnLibcFingerprint(ctx context.Context, text string, attachments map[string]string) []string {
	return tryPwnLibcFingerprint(text, attachments)
}

func solvePwnExploitPattern(ctx context.Context, text string, attachments map[string]string) []string {
	return tryPwnExploitPattern(text, attachments)
}

func solvePwnAdvanced(ctx context.Context, text string, attachments map[string]string) []string {
	return tryPwnAdvanced(text, attachments)
}

// LogRegistryStatus 输出注册表状态（启动时调用）。
func LogRegistryStatus(logger *zap.Logger) {
	if logger == nil {
		return
	}
	solvers := GetSolvers()
	byCat := make(map[SolverCategory]int)
	for _, s := range solvers {
		byCat[s.Category]++
	}
	logger.Info("CTF 求解器注册表",
		zap.Int("total", len(solvers)),
		zap.Int("crypto", byCat[CategoryCryptoS]),
		zap.Int("misc", byCat[CategoryMiscS]),
		zap.Int("web", byCat[CategoryWebS]),
		zap.Int("reverse", byCat[CategoryRevS]),
		zap.Int("pwn", byCat[CategoryPwnS]),
		zap.Int("general", byCat[CategoryAll]),
	)
}

// ── P5 补全适配函数 ──────────────────────────────────────

func solveSymbolicExecution(ctx context.Context, text string, attachments map[string]string) []string {
	return trySymbolicExecution(text, attachments)
}

func solveDynamicAnalysis(ctx context.Context, text string, attachments map[string]string) []string {
	return tryDynamicAnalysis(text, attachments)
}

func solveFirmwareAnalysis(ctx context.Context, text string, attachments map[string]string) []string {
	return tryFirmwareAnalysis(text, attachments)
}

// ── P6 批次适配函数 ──────────────────────────────────────

func solveRSAWiener(ctx context.Context, text string, attachments map[string]string) []string {
	return tryRSAWiener(text, attachments)
}

func solvePohligHellman(ctx context.Context, text string, attachments map[string]string) []string {
	return tryPohligHellman(text, attachments)
}

func solvePaddingOracle(ctx context.Context, text string, attachments map[string]string) []string {
	return tryPaddingOracle(text, attachments)
}

func solveMiscFrequency(ctx context.Context, text string, attachments map[string]string) []string {
	return tryMiscFrequency(text, attachments)
}

func solveWebTemplateInjection(ctx context.Context, text string, attachments map[string]string) []string {
	return tryWebTemplateInjection(text, attachments)
}

func solveBlockchainCTF(ctx context.Context, text string, attachments map[string]string) []string {
	return tryBlockchainCTF(text, attachments)
}

func solveMLSecurity(ctx context.Context, text string, attachments map[string]string) []string {
	return tryMLSecurity(text, attachments)
}

// ── P7 批次适配函数 ──────────────────────────────────────

func solveBrainfuck(ctx context.Context, text string, attachments map[string]string) []string {
	return tryBrainfuck(text)
}

func solveOok(ctx context.Context, text string, attachments map[string]string) []string {
	return tryOok(text)
}

func solveRailFenceVariant(ctx context.Context, text string, attachments map[string]string) []string {
	return tryRailFenceVariant(text)
}

func solveVigenereAutoKey(ctx context.Context, text string, attachments map[string]string) []string {
	return tryVigenereAutoKey(text)
}

// ── P7 crypto 适配函数 ──────────────────────────────────

func solveECDSANonceReuse(ctx context.Context, text string, attachments map[string]string) []string {
	return tryECDSANonceReuse(text, attachments)
}

func solveRSABroadcast(ctx context.Context, text string, attachments map[string]string) []string {
	return tryRSABroadcastComplete(text, attachments)
}

func solveXORMultiByte(ctx context.Context, text string, attachments map[string]string) []string {
	return tryXORMultiByte(text, attachments)
}

// ── P7 web 高级适配函数 ──────────────────────────────────

func solvePrototypePollution(ctx context.Context, text string, attachments map[string]string) []string {
	return tryPrototypePollution(text, attachments)
}

func solveGraphQLBatch(ctx context.Context, text string, attachments map[string]string) []string {
	return tryGraphQLBatch(text, attachments)
}

func solveHTTPRequestSmuggling(ctx context.Context, text string, attachments map[string]string) []string {
	return tryHTTPRequestSmuggling(text, attachments)
}

// ── P8 批次适配函数 ──────────────────────────────────────

// crypto 深水区
func solveEllipticCurve(ctx context.Context, text string, attachments map[string]string) []string {
	return tryEllipticCurve(text, attachments)
}
func solveLatticeLLL(ctx context.Context, text string, attachments map[string]string) []string {
	return tryLatticeLLL(text, attachments)
}
func solvePolynomialDiscreteLog(ctx context.Context, text string, attachments map[string]string) []string {
	return tryPolynomialDiscreteLog(text, attachments)
}

// misc 深水区
func solveDNACoding(ctx context.Context, text string, attachments map[string]string) []string {
	return tryDNACoding(text)
}
func solveBraille(ctx context.Context, text string, attachments map[string]string) []string {
	return tryBraille(text)
}
func solveBarcode(ctx context.Context, text string, attachments map[string]string) []string {
	return tryBarcode(text, attachments)
}

// web 深水区
func solveWebSocketHijack(ctx context.Context, text string, attachments map[string]string) []string {
	return tryWebSocketHijack(text, attachments)
}
func solvePrototypePollutionVariant(ctx context.Context, text string, attachments map[string]string) []string {
	return tryPrototypePollutionVariant(text, attachments)
}

// reverse 深水区
func solveObfuscationDetection(ctx context.Context, text string, attachments map[string]string) []string {
	return tryObfuscationDetection(text, attachments)
}
func solveEmulatorDetection(ctx context.Context, text string, attachments map[string]string) []string {
	return tryEmulatorDetection(text, attachments)
}
func solveCodeVirtualization(ctx context.Context, text string, attachments map[string]string) []string {
	return tryCodeVirtualization(text, attachments)
}
