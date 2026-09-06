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
