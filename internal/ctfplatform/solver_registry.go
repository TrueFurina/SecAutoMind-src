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
	CategoryAll     SolverCategory = "all"     // 全题型通用（如 flag 扫描）
	CategoryCryptoS SolverCategory = "crypto"  // 密码学
	CategoryMiscS   SolverCategory = "misc"    // 杂项
	CategoryWebS    SolverCategory = "web"     // Web 安全
	CategoryRevS    SolverCategory = "reverse" // 逆向工程
	CategoryPwnS    SolverCategory = "pwn"     // 二进制漏洞利用
)

// SolverFunc 求解器函数签名：输入题目描述+附件，返回候选 flag 列表。
// 无命中返回 nil。注意：复用 poller.go 中已定义的 SolverFunc，
// 但注册表使用更通用的 ContextSolverFunc。
type ContextSolverFunc func(ctx context.Context, text string, attachments map[string]string) []string

// SolverEntry 求解器注册条目。
type SolverEntry struct {
	Name     string            // 求解器名（如 "flag_scan"、"rsa_fermat"）
	Category SolverCategory    // 分类（用于按题型过滤）
	Priority int               // 优先级（越小越先执行，0=最高）
	Solver   ContextSolverFunc // 求解函数
	Enabled  bool              // 是否启用
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
	RegisterSolver(SolverEntry{Name: "web_blind_oob", Category: CategoryWebS, Priority: 91, Solver: solveBlindOOB})

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

	// P9 批次
	RegisterSolver(SolverEntry{Name: "elgamal_signature", Category: CategoryCryptoS, Priority: 51, Solver: solveElGamalSignature})
	RegisterSolver(SolverEntry{Name: "schnorr_signature", Category: CategoryCryptoS, Priority: 52, Solver: solveSchnorrSignature})
	RegisterSolver(SolverEntry{Name: "rsa_oracle_attack", Category: CategoryCryptoS, Priority: 53, Solver: solveRSAOracleAttack})
	RegisterSolver(SolverEntry{Name: "exif_metadata", Category: CategoryMiscS, Priority: 79, Solver: solveEXIFMetadata})
	RegisterSolver(SolverEntry{Name: "audio_stego", Category: CategoryMiscS, Priority: 80, Solver: solveAudioStego})
	RegisterSolver(SolverEntry{Name: "magic_bytes", Category: CategoryMiscS, Priority: 81, Solver: solveMagicBytes})
	RegisterSolver(SolverEntry{Name: "waf_bypass", Category: CategoryWebS, Priority: 93, Solver: solveWAFBypass})
	RegisterSolver(SolverEntry{Name: "rce_detection", Category: CategoryWebS, Priority: 94, Solver: solveRCEDetection})
	RegisterSolver(SolverEntry{Name: "file_inclusion", Category: CategoryWebS, Priority: 95, Solver: solveFileInclusion})
	RegisterSolver(SolverEntry{Name: "deserialization", Category: CategoryWebS, Priority: 96, Solver: solveDeserialization})
	RegisterSolver(SolverEntry{Name: "obfuscation_variant", Category: CategoryRevS, Priority: 100, Solver: solveObfuscationVariant})
	RegisterSolver(SolverEntry{Name: "decompiler_chain", Category: CategoryRevS, Priority: 101, Solver: solveDecompilerChain})
	RegisterSolver(SolverEntry{Name: "io_file_exploit", Category: CategoryPwnS, Priority: 103, Solver: solveIOFileExploit})
	RegisterSolver(SolverEntry{Name: "heap_spray", Category: CategoryPwnS, Priority: 104, Solver: solveHeapSpray})

	// P10 批次：crypto
	RegisterSolver(SolverEntry{Name: "homomorphic_encryption", Category: CategoryCryptoS, Priority: 54, Solver: solveHomomorphicEncryption})
	RegisterSolver(SolverEntry{Name: "ec_point_ops", Category: CategoryCryptoS, Priority: 55, Solver: solveECPointOps})
	RegisterSolver(SolverEntry{Name: "lattice_keywords", Category: CategoryCryptoS, Priority: 56, Solver: solveLatticeKeywords})
	// P10 批次：misc 编码变体
	RegisterSolver(SolverEntry{Name: "base32", Category: CategoryMiscS, Priority: 82, Solver: solveBase32})
	RegisterSolver(SolverEntry{Name: "base85", Category: CategoryMiscS, Priority: 83, Solver: solveBase85})
	RegisterSolver(SolverEntry{Name: "base91", Category: CategoryMiscS, Priority: 84, Solver: solveBase91})
	RegisterSolver(SolverEntry{Name: "uuencode", Category: CategoryMiscS, Priority: 85, Solver: solveUUencode})
	RegisterSolver(SolverEntry{Name: "quoted_printable", Category: CategoryMiscS, Priority: 86, Solver: solveQuotedPrintable})
	RegisterSolver(SolverEntry{Name: "punycode", Category: CategoryMiscS, Priority: 87, Solver: solvePunycode})
	// P10 批次：web
	RegisterSolver(SolverEntry{Name: "ssrf_chain", Category: CategoryWebS, Priority: 97, Solver: solveSSRFChain})
	RegisterSolver(SolverEntry{Name: "dom_xss", Category: CategoryWebS, Priority: 98, Solver: solveDOMXSS})
	RegisterSolver(SolverEntry{Name: "stored_xss", Category: CategoryWebS, Priority: 99, Solver: solveStoredXSS})
	// P10 批次：reverse
	RegisterSolver(SolverEntry{Name: "go_reverse_advanced", Category: CategoryRevS, Priority: 102, Solver: solveGoReverseAdvanced})
	RegisterSolver(SolverEntry{Name: "python_reverse", Category: CategoryRevS, Priority: 103, Solver: solvePythonReverseAdvanced})
	RegisterSolver(SolverEntry{Name: "dotnet_reverse", Category: CategoryRevS, Priority: 104, Solver: solveDotNetReverseAdvanced})
	// P10 批次：pwn
	RegisterSolver(SolverEntry{Name: "ret2csu", Category: CategoryPwnS, Priority: 105, Solver: solveRet2csu})
	RegisterSolver(SolverEntry{Name: "ret2syscall", Category: CategoryPwnS, Priority: 106, Solver: solveRet2Syscall})
	RegisterSolver(SolverEntry{Name: "fmt_arbitrary_write", Category: CategoryPwnS, Priority: 107, Solver: solveFormatStringArbitraryWrite})
	RegisterSolver(SolverEntry{Name: "stack_overflow", Category: CategoryPwnS, Priority: 108, Solver: solveStackOverflow})

	// P11 批次：云安全/IoT/移动安全/AI安全/区块链高级/时序攻击/编码变体/新语言逆向/pwn高级
	RegisterSolver(SolverEntry{Name: "cloud_security", Category: CategoryWebS, Priority: 110, Solver: solveCloudSecurity})
	RegisterSolver(SolverEntry{Name: "iot_security", Category: CategoryMiscS, Priority: 111, Solver: solveIoTSecurity})
	RegisterSolver(SolverEntry{Name: "mobile_security", Category: CategoryRevS, Priority: 112, Solver: solveMobileSecurity})
	RegisterSolver(SolverEntry{Name: "ai_ml_security", Category: CategoryMiscS, Priority: 113, Solver: solveAIMLSecurity})
	RegisterSolver(SolverEntry{Name: "blockchain_advanced", Category: CategoryMiscS, Priority: 114, Solver: solveBlockchainAdvanced})
	RegisterSolver(SolverEntry{Name: "timing_attack", Category: CategoryCryptoS, Priority: 57, Solver: solveTimingAttack})
	RegisterSolver(SolverEntry{Name: "z85", Category: CategoryMiscS, Priority: 88, Solver: solveZ85})
	RegisterSolver(SolverEntry{Name: "rust_reverse", Category: CategoryRevS, Priority: 105, Solver: solveRustReverse})
	RegisterSolver(SolverEntry{Name: "swift_reverse", Category: CategoryRevS, Priority: 106, Solver: solveSwiftReverse})
	RegisterSolver(SolverEntry{Name: "wasm_reverse", Category: CategoryRevS, Priority: 107, Solver: solveWebAssemblyReverse})
	RegisterSolver(SolverEntry{Name: "kernel_exploit_advanced", Category: CategoryPwnS, Priority: 109, Solver: solveKernelExploitAdvanced})
	RegisterSolver(SolverEntry{Name: "hypervisor_escape", Category: CategoryPwnS, Priority: 110, Solver: solveHypervisorEscape})
	RegisterSolver(SolverEntry{Name: "firmware_exploit", Category: CategoryPwnS, Priority: 111, Solver: solveFirmwareExploit})

	// P12 批次：密码学算法识别/Web3/汽车安全/卫星安全/编码检测链
	RegisterSolver(SolverEntry{Name: "crypto_algorithm_detect", Category: CategoryCryptoS, Priority: 58, Solver: solveCryptoAlgorithmDetect})
	RegisterSolver(SolverEntry{Name: "encoding_chain", Category: CategoryMiscS, Priority: 89, Solver: solveEncodingChain})
	RegisterSolver(SolverEntry{Name: "web3_security", Category: CategoryMiscS, Priority: 115, Solver: solveWeb3Security})
	RegisterSolver(SolverEntry{Name: "automotive_security", Category: CategoryMiscS, Priority: 116, Solver: solveAutomotiveSecurity})
	RegisterSolver(SolverEntry{Name: "satellite_security", Category: CategoryMiscS, Priority: 117, Solver: solveSatelliteSecurity})
	RegisterSolver(SolverEntry{Name: "advanced_crypto", Category: CategoryCryptoS, Priority: 59, Solver: solveAdvancedCrypto})
	RegisterSolver(SolverEntry{Name: "encoding_advanced", Category: CategoryMiscS, Priority: 90, Solver: solveEncodingDetectionAdvanced})
	RegisterSolver(SolverEntry{Name: "crypto_attack_patterns", Category: CategoryCryptoS, Priority: 60, Solver: solveCryptoAttackPatterns})

	// P13 批次：网络协议安全/数据库安全/无线安全/硬件安全/OS内核/编码变体
	RegisterSolver(SolverEntry{Name: "network_protocol", Category: CategoryWebS, Priority: 100, Solver: solveNetworkProtocol})
	RegisterSolver(SolverEntry{Name: "database_security", Category: CategoryWebS, Priority: 101, Solver: solveDatabaseSecurity})
	RegisterSolver(SolverEntry{Name: "wireless_security", Category: CategoryMiscS, Priority: 118, Solver: solveWirelessSecurity})
	RegisterSolver(SolverEntry{Name: "hardware_security_adv", Category: CategoryMiscS, Priority: 119, Solver: solveHardwareSecurityAdvanced})
	RegisterSolver(SolverEntry{Name: "os_kernel_security", Category: CategoryPwnS, Priority: 112, Solver: solveOSKernelSecurity})
	RegisterSolver(SolverEntry{Name: "base45", Category: CategoryMiscS, Priority: 91, Solver: solveBase45})
	RegisterSolver(SolverEntry{Name: "bech32", Category: CategoryMiscS, Priority: 92, Solver: solveBech32})
	RegisterSolver(SolverEntry{Name: "base62", Category: CategoryMiscS, Priority: 93, Solver: solveBase62})

	// P14 批次：量子计算/生物信息/游戏安全/数字取证高级/密码学实现细节
	RegisterSolver(SolverEntry{Name: "quantum_computing", Category: CategoryMiscS, Priority: 120, Solver: solveQuantumComputing})
	RegisterSolver(SolverEntry{Name: "bioinformatics", Category: CategoryMiscS, Priority: 121, Solver: solveBioinformatics})
	RegisterSolver(SolverEntry{Name: "game_security", Category: CategoryMiscS, Priority: 122, Solver: solveGameSecurity})
	RegisterSolver(SolverEntry{Name: "digital_forensics_adv", Category: CategoryMiscS, Priority: 123, Solver: solveDigitalForensicsAdvanced})
	RegisterSolver(SolverEntry{Name: "crypto_impl_details", Category: CategoryCryptoS, Priority: 61, Solver: solveCryptoImplementationDetails})

	// P15 批次：密码学协议分析/网络取证/漏洞利用链检测
	RegisterSolver(SolverEntry{Name: "crypto_protocol", Category: CategoryCryptoS, Priority: 62, Solver: solveCryptoProtocol})
	RegisterSolver(SolverEntry{Name: "network_forensics", Category: CategoryMiscS, Priority: 94, Solver: solveNetworkForensics})
	RegisterSolver(SolverEntry{Name: "exploit_chain", Category: CategoryPwnS, Priority: 113, Solver: solveExploitChain})

	// P16 批次：crypto 经典攻击完整版（真解题出 flag）
	RegisterSolver(SolverEntry{Name: "common_modulus_attack", Category: CategoryCryptoS, Priority: 63, Solver: solveCommonModulusComplete})
	RegisterSolver(SolverEntry{Name: "hastad_broadcast_attack", Category: CategoryCryptoS, Priority: 64, Solver: solveHastadBroadcastAttack})
	RegisterSolver(SolverEntry{Name: "rsa_wiener_attack", Category: CategoryCryptoS, Priority: 65, Solver: solveRSAWienerAttack})
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
	return trySSTI(fullText, nil)
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

func solveCommonModulusComplete(ctx context.Context, text string, attachments map[string]string) []string {
	return tryCommonModulusComplete(text, attachments)
}

func solveHastadBroadcastAttack(ctx context.Context, text string, attachments map[string]string) []string {
	return tryHastadBroadcastAttack(text, attachments)
}

func solveRSAWienerAttack(ctx context.Context, text string, attachments map[string]string) []string {
	return tryRSAWienerAttack(text, attachments)
}

func solveXORMultiByte(ctx context.Context, text string, attachments map[string]string) []string {
	return tryXORMultiByte(text, attachments)
}

// ── P7 web 高级适配函数 ──────────────────────────────────

func solvePrototypePollution(ctx context.Context, text string, attachments map[string]string) []string {
	return tryPrototypePollution(text, attachments)
}

func solveBlindOOB(ctx context.Context, text string, attachments map[string]string) []string {
	return tryBlindOOB(ctx, text, attachments)
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

// ── P9 批次适配函数 ──────────────────────────────────────

func solveElGamalSignature(ctx context.Context, text string, attachments map[string]string) []string {
	return tryElGamalSignature(text, attachments)
}
func solveSchnorrSignature(ctx context.Context, text string, attachments map[string]string) []string {
	return trySchnorrSignature(text, attachments)
}
func solveRSAOracleAttack(ctx context.Context, text string, attachments map[string]string) []string {
	return tryRSAOracleAttack(text, attachments)
}
func solveEXIFMetadata(ctx context.Context, text string, attachments map[string]string) []string {
	return tryEXIFMetadata(text, attachments)
}
func solveAudioStego(ctx context.Context, text string, attachments map[string]string) []string {
	return tryAudioStego(text, attachments)
}
func solveMagicBytes(ctx context.Context, text string, attachments map[string]string) []string {
	return tryMagicBytes(text, attachments)
}
func solveWAFBypass(ctx context.Context, text string, attachments map[string]string) []string {
	return tryWAFBypass(text, attachments)
}
func solveRCEDetection(ctx context.Context, text string, attachments map[string]string) []string {
	return tryRCEDetection(text, attachments)
}
func solveFileInclusion(ctx context.Context, text string, attachments map[string]string) []string {
	return tryFileInclusion(text, attachments)
}
func solveDeserialization(ctx context.Context, text string, attachments map[string]string) []string {
	return tryDeserialization(text, attachments)
}
func solveObfuscationVariant(ctx context.Context, text string, attachments map[string]string) []string {
	return tryObfuscationVariant(text, attachments)
}
func solveDecompilerChain(ctx context.Context, text string, attachments map[string]string) []string {
	return tryDecompilerChain(text, attachments)
}
func solveIOFileExploit(ctx context.Context, text string, attachments map[string]string) []string {
	return tryIOFileExploit(text, attachments)
}
func solveHeapSpray(ctx context.Context, text string, attachments map[string]string) []string {
	return tryHeapSpray(text, attachments)
}

// ── P10 批次适配函数 ──────────────────────────────────────

// crypto
func solveHomomorphicEncryption(ctx context.Context, text string, attachments map[string]string) []string {
	return tryHomomorphicEncryption(text, attachments)
}
func solveECPointOps(ctx context.Context, text string, attachments map[string]string) []string {
	return tryEllipticCurvePointOps(text, attachments)
}
func solveLatticeKeywords(ctx context.Context, text string, attachments map[string]string) []string {
	return tryLatticeKeywords(text, attachments)
}

// misc 编码变体
func solveBase32(ctx context.Context, text string, attachments map[string]string) []string {
	return tryBase32(text)
}
func solveBase85(ctx context.Context, text string, attachments map[string]string) []string {
	return tryBase85(text)
}
func solveBase91(ctx context.Context, text string, attachments map[string]string) []string {
	return tryBase91(text)
}
func solveUUencode(ctx context.Context, text string, attachments map[string]string) []string {
	return tryUUencode(text)
}
func solveQuotedPrintable(ctx context.Context, text string, attachments map[string]string) []string {
	return tryQuotedPrintable(text)
}
func solvePunycode(ctx context.Context, text string, attachments map[string]string) []string {
	return tryPunycode(text)
}

// web
func solveSSRFChain(ctx context.Context, text string, attachments map[string]string) []string {
	return trySSRFChain(text, attachments)
}
func solveDOMXSS(ctx context.Context, text string, attachments map[string]string) []string {
	return tryDOMXSS(text, attachments)
}
func solveStoredXSS(ctx context.Context, text string, attachments map[string]string) []string {
	return tryStoredXSS(text, attachments)
}

// reverse
func solveGoReverseAdvanced(ctx context.Context, text string, attachments map[string]string) []string {
	return tryGoReverseAdvanced(text, attachments)
}
func solvePythonReverseAdvanced(ctx context.Context, text string, attachments map[string]string) []string {
	return tryPythonReverseAdvanced(text, attachments)
}
func solveDotNetReverseAdvanced(ctx context.Context, text string, attachments map[string]string) []string {
	return tryDotNetReverseAdvanced(text, attachments)
}

// pwn
func solveRet2csu(ctx context.Context, text string, attachments map[string]string) []string {
	return tryRet2csu(text, attachments)
}
func solveRet2Syscall(ctx context.Context, text string, attachments map[string]string) []string {
	return tryRet2Syscall(text, attachments)
}
func solveFormatStringArbitraryWrite(ctx context.Context, text string, attachments map[string]string) []string {
	return tryFormatStringArbitraryWrite(text, attachments)
}
func solveStackOverflow(ctx context.Context, text string, attachments map[string]string) []string {
	return tryStackOverflow(text, attachments)
}

// ── P11 批次适配函数 ──────────────────────────────────────

func solveCloudSecurity(ctx context.Context, text string, attachments map[string]string) []string {
	return tryCloudSecurity(text, attachments)
}
func solveIoTSecurity(ctx context.Context, text string, attachments map[string]string) []string {
	return tryIoTSecurity(text, attachments)
}
func solveMobileSecurity(ctx context.Context, text string, attachments map[string]string) []string {
	return tryMobileSecurity(text, attachments)
}
func solveAIMLSecurity(ctx context.Context, text string, attachments map[string]string) []string {
	return tryAIMLSecurity(text, attachments)
}
func solveBlockchainAdvanced(ctx context.Context, text string, attachments map[string]string) []string {
	return tryBlockchainAdvanced(text, attachments)
}
func solveTimingAttack(ctx context.Context, text string, attachments map[string]string) []string {
	return tryTimingAttack(text, attachments)
}
func solveZ85(ctx context.Context, text string, attachments map[string]string) []string {
	return tryZ85(text)
}
func solveRustReverse(ctx context.Context, text string, attachments map[string]string) []string {
	return tryRustReverse(text, attachments)
}
func solveSwiftReverse(ctx context.Context, text string, attachments map[string]string) []string {
	return trySwiftReverse(text, attachments)
}
func solveWebAssemblyReverse(ctx context.Context, text string, attachments map[string]string) []string {
	return tryWebAssemblyReverse(text, attachments)
}
func solveKernelExploitAdvanced(ctx context.Context, text string, attachments map[string]string) []string {
	return tryKernelExploitAdvanced(text, attachments)
}
func solveHypervisorEscape(ctx context.Context, text string, attachments map[string]string) []string {
	return tryHypervisorEscape(text, attachments)
}
func solveFirmwareExploit(ctx context.Context, text string, attachments map[string]string) []string {
	return tryFirmwareExploit(text, attachments)
}

// ── P12 批次适配函数 ──────────────────────────────────────

func solveCryptoAlgorithmDetect(ctx context.Context, text string, attachments map[string]string) []string {
	return tryCryptoAlgorithmDetect(text, attachments)
}
func solveEncodingChain(ctx context.Context, text string, attachments map[string]string) []string {
	return tryEncodingChain(text, attachments)
}
func solveWeb3Security(ctx context.Context, text string, attachments map[string]string) []string {
	return tryWeb3Security(text, attachments)
}
func solveAutomotiveSecurity(ctx context.Context, text string, attachments map[string]string) []string {
	return tryAutomotiveSecurity(text, attachments)
}
func solveSatelliteSecurity(ctx context.Context, text string, attachments map[string]string) []string {
	return trySatelliteSecurity(text, attachments)
}
func solveAdvancedCrypto(ctx context.Context, text string, attachments map[string]string) []string {
	return tryAdvancedCrypto(text, attachments)
}
func solveEncodingDetectionAdvanced(ctx context.Context, text string, attachments map[string]string) []string {
	return tryEncodingDetectionAdvanced(text, attachments)
}
func solveCryptoAttackPatterns(ctx context.Context, text string, attachments map[string]string) []string {
	return tryCryptoAttackPatterns(text, attachments)
}

// ── P13 批次适配函数 ──────────────────────────────────────

func solveNetworkProtocol(ctx context.Context, text string, attachments map[string]string) []string {
	return tryNetworkProtocol(text, attachments)
}
func solveDatabaseSecurity(ctx context.Context, text string, attachments map[string]string) []string {
	return tryDatabaseSecurity(text, attachments)
}
func solveWirelessSecurity(ctx context.Context, text string, attachments map[string]string) []string {
	return tryWirelessSecurity(text, attachments)
}
func solveHardwareSecurityAdvanced(ctx context.Context, text string, attachments map[string]string) []string {
	return tryHardwareSecurityAdvanced(text, attachments)
}
func solveOSKernelSecurity(ctx context.Context, text string, attachments map[string]string) []string {
	return tryOSKernelSecurity(text, attachments)
}
func solveBase45(ctx context.Context, text string, attachments map[string]string) []string {
	return tryBase45(text)
}
func solveBech32(ctx context.Context, text string, attachments map[string]string) []string {
	return tryBech32(text)
}
func solveBase62(ctx context.Context, text string, attachments map[string]string) []string {
	return tryBase62(text)
}

// ── P14 批次适配函数 ──────────────────────────────────────

func solveQuantumComputing(ctx context.Context, text string, attachments map[string]string) []string {
	return tryQuantumComputing(text, attachments)
}
func solveBioinformatics(ctx context.Context, text string, attachments map[string]string) []string {
	return tryBioinformatics(text, attachments)
}
func solveGameSecurity(ctx context.Context, text string, attachments map[string]string) []string {
	return tryGameSecurity(text, attachments)
}
func solveDigitalForensicsAdvanced(ctx context.Context, text string, attachments map[string]string) []string {
	return tryDigitalForensicsAdvanced(text, attachments)
}
func solveCryptoImplementationDetails(ctx context.Context, text string, attachments map[string]string) []string {
	return tryCryptoImplementationDetails(text, attachments)
}

// ── P15 批次适配函数 ──────────────────────────────────────

func solveCryptoProtocol(ctx context.Context, text string, attachments map[string]string) []string {
	return tryCryptoProtocolAnalysis(text, attachments)
}
func solveNetworkForensics(ctx context.Context, text string, attachments map[string]string) []string {
	return tryNetworkForensics(text, attachments)
}
func solveExploitChain(ctx context.Context, text string, attachments map[string]string) []string {
	return tryExploitChainDetection(text, attachments)
}

// ── P1 真解题求解器适配函数 ──────────────────────────────────

func solveVigenereDecode(ctx context.Context, text string, attachments map[string]string) []string {
	return tryVigenereDecode(text)
}
func solveAtbashDecode(ctx context.Context, text string, attachments map[string]string) []string {
	return tryAtbashDecode(text)
}
func solveROT13(ctx context.Context, text string, attachments map[string]string) []string {
	return tryROT13(text)
}
func solveHexDecode(ctx context.Context, text string, attachments map[string]string) []string {
	return tryHexDecode(text)
}
func solveURLDecode(ctx context.Context, text string, attachments map[string]string) []string {
	return tryURLDecode(text)
}
func solveBinaryDecode(ctx context.Context, text string, attachments map[string]string) []string {
	return tryBinaryDecode(text)
}
func solveOctalDecode(ctx context.Context, text string, attachments map[string]string) []string {
	return tryOctalDecode(text)
}
func solveDecimalDecode(ctx context.Context, text string, attachments map[string]string) []string {
	return tryDecimalDecode(text)
}
func solveReverseText(ctx context.Context, text string, attachments map[string]string) []string {
	return tryReverseText(text)
}
func solvePigLatin(ctx context.Context, text string, attachments map[string]string) []string {
	return tryPigLatin(text)
}
func solveBase64URLSafe(ctx context.Context, text string, attachments map[string]string) []string {
	return tryBase64URLSafe(text)
}
