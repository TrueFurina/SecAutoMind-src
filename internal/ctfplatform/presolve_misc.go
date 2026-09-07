// presolve_misc.go —— 新兴领域与杂项求解器（云/IoT/车联/卫星/区块链等）
// 自 presolve.go 机械拆分（22 个声明），内容零改动；数字口径见 scripts/count_stats.py。
package ctfplatform

import (
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// Presolve 对题目描述/附件内容执行全部确定性求解器（并行扇出）。
// 命中即返回候选 flag；未命中返回 solved=false。
func (p *Presolver) Presolve(ctx context.Context, ch *Challenge, attachments map[string]string) *PresolveResult {
	text := ch.Description
	for _, v := range attachments {
		text += "\n" + v
	}
	if strings.TrimSpace(text) == "" {
		return &PresolveResult{}
	}

	// 并行扇出所有求解器
	type result struct {
		engine string
		flags  []string
	}
	chResult := make(chan result, 8)
	var wg sync.WaitGroup

	// 1. flag 正则扫描（全题型兜底）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := scanFlags(text)
		if len(flags) > 0 {
			chResult <- result{"flag_scan", flags}
		}
	}()

	// 2. 多层 base64 解码
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryBase64Multilayer(text)
		if len(flags) > 0 {
			chResult <- result{"base64_multilayer", flags}
		}
	}()

	// 3. 凯撒爆破（仅对短文本）
	wg.Add(1)
	go func() {
		defer wg.Done()
		if len(text) < 500 {
			flags := tryCaesar(text)
			if len(flags) > 0 {
				chResult <- result{"caesar", flags}
			}
		}
	}()

	// 4. XOR 单字节（hex 串或短文本）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryXOR(text)
		if len(flags) > 0 {
			chResult <- result{"xor_single", flags}
		}
	}()

	// 5. 哈希爆破（匹配常见哈希格式）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryHashCrack(text)
		if len(flags) > 0 {
			chResult <- result{"hash_crack", flags}
		}
	}()

	// 5b. Morse 解码
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryMorse(text)
		if len(flags) > 0 {
			chResult <- result{"morse", flags}
		}
	}()

	// 5c. 维吉尼亚解码（已知密钥或短密文）
	wg.Add(1)
	go func() {
		defer wg.Done()
		if len(text) < 300 {
			flags := tryVigenere(text)
			if len(flags) > 0 {
				chResult <- result{"vigenere", flags}
			}
		}
	}()

	// 5d. ZIP 伪加密检测
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryZIPFakeEncryption(text)
		if len(flags) > 0 {
			chResult <- result{"zip_fake_enc", flags}
		}
	}()

	// 5e. Web 源码审计关键词（flag 注释/备份文件/敏感路径）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryWebSourceAudit(text, attachments)
		if len(flags) > 0 {
			chResult <- result{"web_source_audit", flags}
		}
	}()

	// 5f. SSTI 模板注入检测
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := trySSTI(text)
		if len(flags) > 0 {
			chResult <- result{"ssti", flags}
		}
	}()

	// 6. RSA 模板匹配（费马/小指数/高指数/PKCS#1）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryRSATemplate(text)
		if len(flags) > 0 {
			chResult <- result{"rsa_template", flags}
		}
	}()

	// 7. Legendre 符号攻击（phi 泄露型）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryLegendrePhi(text)
		if len(flags) > 0 {
			chResult <- result{"legendre_phi", flags}
		}
	}()

	// 8. 模逆攻击（phi+dual-modular-inverse）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryModInvFactor(text)
		if len(flags) > 0 {
			chResult <- result{"modinv_factor", flags}
		}
	}()

	// 9. RSA 共享素数分解（gcd(n1,n2)=p 型）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryCommonFactor(text)
		if len(flags) > 0 {
			chResult <- result{"rsa_common_factor", flags}
		}
	}()

	// 10. 大小端序转换（hex 组内字节反转）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryEndian(text)
		if len(flags) > 0 {
			chResult <- result{"endian", flags}
		}
	}()

	// 11. 栅栏密码（栏数 2-8 暴力，整串+逐 token）
	wg.Add(1)
	go func() {
		defer wg.Done()
		flags := tryRailFence(text)
		if len(flags) > 0 {
			chResult <- result{"rail_fence", flags}
		}
	}()

	// 等待所有求解器完成
	go func() {
		wg.Wait()
		close(chResult)
	}()

	// 收集全部命中，按确定性优先级选择：
	// base64_multilayer(hunt: 维吉尼亚→扫描→凯撒→b64 递归链) 最高——其内部扫描
	// 只在维吉尼亚失败后才触发，答案质量高于裸 flag_scan；
	// flag_scan 排最后（大写品牌兜底误报率最高，如凯撒中间态形似 flag）。
	priority := map[string]int{
		"base64_multilayer": 0,
		"vigenere":          1,
		"caesar":            2,
		"morse":             3,
		"rsa_template":      4,
		"rsa_common_factor": 4,
		"endian":            4,
		"rail_fence":        4,
		"legendre_phi":      5,
		"modinv_factor":     6,
		"hash_crack":        7,
		"xor_single":        8,
		"web_source_audit":  9,
		"zip_fake_enc":      10,
		"ssti":              11,
		"flag_scan":         12,
	}
	var best *result
	for r := range chResult {
		if len(r.flags) == 0 {
			continue
		}
		if best == nil || priority[r.engine] < priority[best.engine] {
			r := r
			best = &r
		}
	}
	if best != nil {
		p.logger.Info("presolve 命中",
			zap.String("engine", best.engine),
			zap.Strings("flags", best.flags))
		return &PresolveResult{
			Flags:  best.flags,
			Engine: best.engine,
			Solved: true,
			Detail: fmt.Sprintf("[presolve:%s] 命中 %d 个候选", best.engine, len(best.flags)),
		}
	}

	return &PresolveResult{Solved: false, Detail: "presolve 未命中，需 LLM 推理"}
}

// tryAESECB 检测 AES ECB 模式特征（重复块 = 重复明文）。
func tryAESECB(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	// 检测 hex 密文中是否有重复 16 字节块（AES 块大小）
	hexRe := regexp.MustCompile(`[0-9a-fA-F]{32,}`)
	for _, m := range hexRe.FindAllString(fullText, -1) {
		data, err := hex.DecodeString(m)
		if err != nil || len(data) < 32 {
			continue
		}
		// 检查是否有重复的 16 字节块
		blocks := make(map[string]int)
		for i := 0; i+16 <= len(data); i += 16 {
			block := string(data[i : i+16])
			blocks[block]++
		}
		for block, count := range blocks {
			if count >= 2 {
				_ = block
				return []string{fmt.Sprintf("AES ECB 检测：发现 %d 个重复的 16 字节块（ECB 模式特征，相同明文块→相同密文块）", count)}
			}
		}
	}
	// 关键词检测
	lower := strings.ToLower(fullText)
	if strings.Contains(lower, "ecb") && (strings.Contains(lower, "aes") || strings.Contains(lower, "block")) {
		return []string{"AES ECB 模式关键词检测：ECB 模式不隐藏明文模式，可利用重复块分析"}
	}
	return nil
}

// trySecondOrderInjection 检测二次注入特征。
func trySecondOrderInjection(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	soKeywords := []struct {
		keyword string
		hint    string
	}{
		{"second order", "二次注入：存储后再触发的注入攻击"},
		{"stored injection", "存储型注入"},
		{"stored xss", "存储型 XSS"},
		{"blind injection", "盲注入"},
		{"blind sql", "SQL 盲注"},
		{"blind xss", "XSS 盲注"},
		{"out-of-band", "带外注入（OOB）"},
		{"dns exfiltration", "DNS 数据外泄"},
		{"http callback", "HTTP 回调检测"},
		{"burp collaborator", "Burp Collaborator 带外检测"},
	}
	for _, kw := range soKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"注入特征: " + kw.hint}
		}
	}
	return nil
}

// tryMultipartBoundary 检测 multipart 表单边界特征（文件上传/边界绕过）。
func tryMultipartBoundary(text string) []string {
	lower := strings.ToLower(text)
	if strings.Contains(lower, "multipart/form-data") || strings.Contains(lower, "boundary=") {
		return []string{"Multipart 表单：可能含文件上传或边界绕过漏洞"}
	}
	return nil
}

// tryFirmwareAnalysis 检测固件分析特征。
func tryFirmwareAnalysis(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	fwKeywords := []struct {
		keyword string
		hint    string
	}{
		{"firmware", "固件分析"},
		{"firmware extraction", "固件提取"},
		{"binwalk", "Binwalk 固件分析工具"},
		{"squashfs", "SquashFS 文件系统"},
		{"cramfs", "CramFS 文件系统"},
		{"uboot", "U-Boot 引导加载程序"},
		{"openwrt", "OpenWrt 路由器固件"},
		{"router", "路由器固件"},
		{"iot", "物联网设备"},
		{"embedded", "嵌入式系统"},
		{"rtos", "实时操作系统"},
		{"arm firmware", "ARM 固件"},
		{"mips firmware", "MIPS 固件"},
		{"repack", "固件重打包"},
		{"emulation", "固件模拟"},
		{"qemu", "QEMU 模拟器"},
	}
	for _, kw := range fwKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"固件分析: " + kw.hint}
		}
	}
	return nil
}

// tryMiscFrequency 检测频率分析/字符统计特征（替换密码/古典密码）。
func tryMiscFrequency(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	freqKeywords := []struct {
		keyword string
		hint    string
	}{
		{"frequency analysis", "频率分析：破解替换密码"},
		{"substitution cipher", "替换密码"},
		{"monoalphabetic", "单表替换密码"},
		{"polyalphabetic", "多表替换密码"},
		{"playfair", "Playfair 密码"},
		{"hill cipher", "Hill 密码"},
		{"atbash", "Atbash 密码"},
		{"pigpen", "猪圈密码"},
		{"polybius", "Polybius 方阵"},
		{"ascii", "ASCII 编码"},
		{"rot13", "ROT13 编码"},
		{"rot47", "ROT47 编码"},
		{"unicode", "Unicode 编码"},
		{"utf-8", "UTF-8 编码"},
		{"hex encoding", "十六进制编码"},
		{"octal", "八进制编码"},
		{"binary encoding", "二进制编码"},
		{"decimal encoding", "十进制编码"},
	}
	for _, kw := range freqKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"编码/密码: " + kw.hint}
		}
	}
	return nil
}

// tryBlockchainCTF 检测区块链 CTF 特征（以太坊/智能合约）。
func tryBlockchainCTF(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	bcKeywords := []struct {
		keyword string
		hint    string
	}{
		{"ethereum", "以太坊"},
		{"solidity", "Solidity 智能合约"},
		{"smart contract", "智能合约"},
		{"evm", "以太坊虚拟机（EVM）"},
		{"metamask", "MetaMask 钱包"},
		{"web3", "Web3.js 库"},
		{"ethers", "Ethers.js 库"},
		{"reentrancy", "重入攻击（智能合约）"},
		{"integer overflow", "整数溢出（Solidity <0.8）"},
		{"delegatecall", "Delegatecall 漏洞"},
		{"selfdestruct", "Selfdestruct 攻击"},
		{"tx.origin", "tx.origin 钓鱼攻击"},
		{"flash loan", "闪电贷攻击"},
		{"frontrunning", "抢跑交易（MEV）"},
		{"dex", "去中心化交易所（DEX）"},
		{"erc20", "ERC-20 代币标准"},
		{"erc721", "ERC-721 NFT 标准"},
		{"nonce", "交易 Nonce"},
		{"gas", "Gas 费用"},
		{"wei", "Wei（以太坊最小单位）"},
	}
	for _, kw := range bcKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"区块链CTF: " + kw.hint}
		}
	}
	return nil
}

// tryMLSecurity 检测机器学习安全特征（对抗样本/模型窃取）。
func tryMLSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	mlKeywords := []struct {
		keyword string
		hint    string
	}{
		{"adversarial example", "对抗样本"},
		{"adversarial attack", "对抗攻击"},
		{"model inversion", "模型逆向攻击"},
		{"model stealing", "模型窃取"},
		{"data poisoning", "数据投毒攻击"},
		{"prompt injection", "Prompt 注入攻击（LLM）"},
		{"jailbreak", "越狱攻击（LLM）"},
		{"prompt leaking", "Prompt 泄露"},
		{"neural network", "神经网络"},
		{"machine learning", "机器学习"},
		{"deep learning", "深度学习"},
		{"classification", "分类任务"},
		{"regression", "回归任务"},
	}
	for _, kw := range mlKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"AI安全: " + kw.hint}
		}
	}
	return nil
}

// tryCloudSecurity 检测云安全误配置/攻击特征。
func tryCloudSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	cloudKeywords := []struct {
		keyword string
		hint    string
	}{
		{"aws", "Amazon Web Services"},
		{"ec2", "EC2 实例"},
		{"s3 bucket", "S3 存储桶"},
		{"lambda", "AWS Lambda"},
		{"iam", "AWS IAM 权限"},
		{"cloudtrail", "CloudTrail 审计"},
		{"sts", "AWS STS 临时凭证"},
		{"access key", "AWS Access Key"},
		{"secret key", "AWS Secret Key"},
		{"gcp", "Google Cloud Platform"},
		{"gcs", "Google Cloud Storage"},
		{"compute engine", "GCP Compute Engine"},
		{"service account", "GCP Service Account"},
		{"azure", "Microsoft Azure"},
		{"blob storage", "Azure Blob Storage"},
		{"cosmos db", "Azure Cosmos DB"},
		{"active directory", "Azure AD"},
		{"managed identity", "Azure Managed Identity"},
		{"kubernetes", "Kubernetes 容器编排"},
		{"docker", "Docker 容器"},
		{"container escape", "容器逃逸"},
		{"privilege escalation", "权限提升"},
		{"misconfiguration", "配置错误"},
		{"exposed", "暴露/泄露"},
		{"public access", "公共访问"},
		{"anonymous", "匿名访问"},
		{"metadata service", "元数据服务"},
		{"imds", "实例元数据服务"},
		{"ssrf to cloud", "SSRF → 云元数据"},
	}
	for _, kw := range cloudKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"云安全: " + kw.hint}
		}
	}
	return nil
}

// tryIoTSecurity 检测 IoT 安全特征。
func tryIoTSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	iotKeywords := []struct {
		keyword string
		hint    string
	}{
		{"iot", "物联网"},
		{"mqtt", "MQTT 协议"},
		{"coap", "CoAP 协议"},
		{"zigbee", "Zigbee 协议"},
		{"z-wave", "Z-Wave 协议"},
		{"bluetooth", "蓝牙协议"},
		{"ble", "低功耗蓝牙"},
		{"lorawan", "LoRaWAN 协议"},
		{"embedded", "嵌入式系统"},
		{"rtos", "实时操作系统"},
		{"firmware", "固件"},
		{"embedded linux", "嵌入式 Linux"},
		{"openwrt", "OpenWrt 路由器"},
		{"router exploit", "路由器漏洞利用"},
		{"scada", "SCADA 工控系统"},
		{"ics", "工业控制系统"},
		{"plc", "可编程逻辑控制器"},
		{"modbus", "Modbus 协议"},
		{"opc", "OPC 协议"},
		{"smart home", "智能家居"},
		{"ip camera", "IP 摄像头"},
		{"default credentials", "默认凭据"},
		{"hardcoded password", "硬编码密码"},
	}
	for _, kw := range iotKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"IoT安全: " + kw.hint}
		}
	}
	return nil
}

// tryMobileSecurity 检测移动安全特征（Android/iOS）。
func tryMobileSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	mobileKeywords := []struct {
		keyword string
		hint    string
	}{
		{"android", "Android 平台"},
		{"ios", "iOS 平台"},
		{"apk", "Android APK"},
		{"ipa", "iOS IPA"},
		{"smali", "Smali 反汇编"},
		{"dalvik", "Dalvik 虚拟机"},
		{"art", "ART 运行时"},
		{"dex", "DEX 字节码"},
		{"apktool", "APKTool"},
		{"jadx", "JADX 反编译"},
		{"frida", "Frida 动态插桩"},
		{"xposed", "Xposed 框架"},
		{"magisk", "Magisk Root"},
		{"cydia", "Cydia（越狱）"},
		{"checkra1n", "checkra1n 越狱"},
		{"unc0ver", "unc0ver 越狱"},
		{"ssl pinning", "SSL Pinning"},
		{"certificate pinning", "证书固定"},
		{"jailbreak detection", "越狱检测"},
		{"root detection", "Root 检测"},
		{"emulator detection", "模拟器检测"},
		{"deep link", "Deep Link"},
		{"intent", "Android Intent"},
		{"content provider", "Content Provider"},
		{"broadcast receiver", "Broadcast Receiver"},
		{"webview", "WebView"},
		{"sqlite", "SQLite 数据库"},
		{"keychain", "iOS Keychain"},
		{"shared preferences", "SharedPreferences"},
	}
	for _, kw := range mobileKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"移动安全: " + kw.hint}
		}
	}
	return nil
}

// tryAIMLSecurity 检测 AI/ML 安全特征。
func tryAIMLSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	aiKeywords := []struct {
		keyword string
		hint    string
	}{
		{"adversarial example", "对抗样本"},
		{"adversarial attack", "对抗攻击"},
		{"model inversion", "模型逆向攻击"},
		{"model stealing", "模型窃取"},
		{"data poisoning", "数据投毒"},
		{"prompt injection", "Prompt 注入攻击"},
		{"jailbreak", "LLM 越狱攻击"},
		{"prompt leaking", "Prompt 泄露"},
		{"training data extraction", "训练数据提取"},
		{"membership inference", "成员推断攻击"},
		{"differential privacy", "差分隐私"},
		{"federated learning", "联邦学习"},
		{"adversarial patch", "对抗补丁"},
		{"backdoor attack", "后门攻击"},
		{"model watermark", "模型水印"},
		{"neural network", "神经网络"},
		{"machine learning", "机器学习"},
		{"deep learning", "深度学习"},
	}
	for _, kw := range aiKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"AI安全: " + kw.hint}
		}
	}
	return nil
}

// tryBlockchainAdvanced 检测区块链安全高级特征。
func tryBlockchainAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	bcKeywords := []struct {
		keyword string
		hint    string
	}{
		{"reentrancy", "重入攻击"},
		{"integer overflow", "整数溢出"},
		{"flash loan", "闪电贷攻击"},
		{"frontrunning", "抢跑交易"},
		{"sandwich attack", "三明治攻击"},
		{"oracle manipulation", "预言机操纵"},
		{"governance attack", "治理攻击"},
		{"rug pull", "Rug Pull"},
		{"honeypot", "蜜罐合约"},
		{"abi encoding", "ABI 编码"},
		{"calldata", "Calldata 注入"},
		{"delegatecall", "Delegatecall 漏洞"},
		{"selfdestruct", "Selfdestruct 攻击"},
		{"tx.origin", "tx.origin 钓鱼"},
		{"proxy contract", "代理合约"},
		{"upgradeable", "可升级合约"},
		{"diamond pattern", "Diamond 模式"},
		{"erc20 approval", "ERC-20 授权漏洞"},
		{"permit", "EIP-2612 Permit"},
		{"mev", "MEV（最大可提取价值）"},
		{"cross-chain", "跨链安全"},
		{"bridge", "跨链桥安全"},
		{"l2 security", "L2 安全"},
	}
	for _, kw := range bcKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"区块链高级: " + kw.hint}
		}
	}
	return nil
}

// tryTimingAttack 检测时序攻击/功耗分析特征。
func tryTimingAttack(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	taKeywords := []struct {
		keyword string
		hint    string
	}{
		{"timing attack", "时序攻击"},
		{"timing side channel", "时序侧信道"},
		{"cache timing", "缓存时序"},
		{"branch prediction", "分支预测侧信道"},
		{"speculative execution", "推测执行"},
		{"spectre", "Spectre 漏洞"},
		{"meltdown", "Meltdown 漏洞"},
		{"power analysis", "功耗分析"},
		{"differential power", "差分功耗分析（DPA）"},
		{"simple power", "简单功耗分析（SPA）"},
		{"electromagnetic", "电磁侧信道"},
		{"acoustic", "声学侧信道"},
		{"fault injection", "故障注入"},
		{"rowhammer", "Rowhammer DRAM"},
		{"cold boot", "冷启动攻击"},
		{"hardware security", "硬件安全"},
		{"tpm", "可信平台模块"},
		{"secure enclave", "安全飞地"},
		{"sgx", "Intel SGX"},
		{"trustzone", "ARM TrustZone"},
	}
	for _, kw := range taKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"侧信道: " + kw.hint}
		}
	}
	return nil
}

// tryAutomotiveSecurity 检测汽车安全特征（CAN总线/车载网络/ADAS）。
func tryAutomotiveSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	autoKeywords := []struct {
		keyword string
		hint    string
	}{
		{"can bus", "CAN 总线"},
		{"canbus", "CAN 总线"},
		{"obd", "OBD 诊断接口"},
		{"obd-ii", "OBD-II 接口"},
		{"uds", "统一诊断服务（UDS）"},
		{"automotive", "汽车安全"},
		{"connected car", "车联网"},
		{"v2x", "车对万物通信（V2X）"},
		{"adas", "高级驾驶辅助系统（ADAS）"},
		{"autonomous driving", "自动驾驶"},
		{"lidar", "激光雷达"},
		{"radar", "毫米波雷达"},
		{"tesla", "特斯拉"},
		{"can injection", "CAN 注入攻击"},
		{"can sniffing", "CAN 嗅探"},
		{"ecu", "电子控制单元（ECU）"},
		{"firmware update", "OTA 固件更新"},
		{"vehicle security", "车辆安全"},
		{"immobilizer", "防盗系统"},
		{"key fob", "遥控钥匙"},
		{"relay attack", "中继攻击"},
		{"tpms", "胎压监测系统"},
	}
	for _, kw := range autoKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"汽车安全: " + kw.hint}
		}
	}
	return nil
}

// trySatelliteSecurity 检测卫星安全特征（卫星通信/遥测/地面站）。
func trySatelliteSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	satKeywords := []struct {
		keyword string
		hint    string
	}{
		{"satellite", "卫星安全"},
		{"satellite communication", "卫星通信"},
		{"satcom", "卫星通信（SATCOM）"},
		{"telemetry", "遥测"},
		{"telecommand", "遥控指令"},
		{"ground station", "地面站"},
		{"uplink", "上行链路"},
		{"downlink", "下行链路"},
		{"gnss", "全球导航卫星系统（GNSS）"},
		{"gps spoofing", "GPS 欺骗"},
		{"gps jamming", "GPS 干扰"},
		{"signal jamming", "信号干扰"},
		{"frequency hopping", "跳频"},
		{"spread spectrum", "扩频"},
		{"modulation", "调制"},
		{"demodulation", "解调"},
		{"signal analysis", "信号分析"},
		{"sdr", "软件定义无线电（SDR）"},
		{"rtl-sdr", "RTL-SDR"},
		{"gnu radio", "GNU Radio"},
		{"iq data", "IQ 数据"},
		{"constellation", "星座图"},
		{"spectrum analysis", "频谱分析"},
		{"interference", "干扰"},
	}
	for _, kw := range satKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"卫星安全: " + kw.hint}
		}
	}
	return nil
}

// tryNetworkProtocol 检测网络协议安全特征（TCP/IP/DNS/HTTP2/QUIC等）。
func tryNetworkProtocol(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	protoKeywords := []struct {
		keyword string
		hint    string
	}{
		{"tcp/ip", "TCP/IP 协议栈"},
		{"tcp reset", "TCP RST 注入"},
		{"tcp sequence", "TCP 序列号预测"},
		{"syn flood", "SYN 洪泛攻击"},
		{"dns poisoning", "DNS 投毒"},
		{"dns rebinding", "DNS 重绑定"},
		{"dns tunneling", "DNS 隧道"},
		{"dns exfiltration", "DNS 数据外泄"},
		{"dnssec", "DNSSEC"},
		{"http/2", "HTTP/2 协议"},
		{"http/3", "HTTP/3 协议"},
		{"quic", "QUIC 协议"},
		{"server-sent events", "SSE 服务器推送"},
		{"grpc", "gRPC 协议"},
		{"protobuf", "Protocol Buffers"},
		{"graphql subscription", "GraphQL 订阅"},
		{"websocket upgrade", "WebSocket 升级握手"},
		{"hsts", "HSTS 严格传输安全"},
		{"csp", "内容安全策略（CSP）"},
		{"cors misconfiguration", "CORS 配置错误"},
		{"host header injection", "Host 头注入"},
		{"request smuggling", "HTTP 请求走私"},
		{"cache poisoning", "缓存投毒"},
		{"clickjacking", "点击劫持"},
	}
	for _, kw := range protoKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"网络协议: " + kw.hint}
		}
	}
	return nil
}

// tryDatabaseSecurity 检测数据库安全特征（SQL注入变体/NoSQL注入）。
func tryDatabaseSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	dbKeywords := []struct {
		keyword string
		hint    string
	}{
		{"sql injection", "SQL 注入"},
		{"nosql injection", "NoSQL 注入"},
		{"mongodb injection", "MongoDB 注入"},
		{"couchdb", "CouchDB 注入"},
		{"redis injection", "Redis 注入"},
		{"ldap injection", "LDAP 注入"},
		{"xpath injection", "XPath 注入"},
		{"xml injection", "XML 注入"},
		{"orm injection", "ORM 注入"},
		{"second order injection", "二次注入"},
		{"blind sql injection", "SQL 盲注"},
		{"time-based sql", "时间盲注"},
		{"union select", "UNION 注入"},
		{"error-based sql", "报错注入"},
		{"stacked queries", "堆叠查询"},
		{"information_schema", "INFORMATION_SCHEMA"},
		{"mysql", "MySQL"},
		{"postgresql", "PostgreSQL"},
		{"sqlite", "SQLite"},
		{"oracle", "Oracle"},
		{"mssql", "Microsoft SQL Server"},
		{"cassandra", "Cassandra"},
		{"neo4j", "Neo4j 图数据库"},
	}
	for _, kw := range dbKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"数据库安全: " + kw.hint}
		}
	}
	return nil
}

// tryWirelessSecurity 检测无线安全特征（WiFi/Bluetooth/NFC/RFID）。
func tryWirelessSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	wlKeywords := []struct {
		keyword string
		hint    string
	}{
		{"wifi", "WiFi 安全"},
		{"wpa2", "WPA2 加密"},
		{"wpa3", "WPA3 加密"},
		{"wep", "WEP 加密"},
		{"deauthentication", "解除认证攻击"},
		{"evil twin", "Evil Twin 攻击"},
		{"evil ap", "Evil AP 攻击"},
		{"rogue ap", "Rogue AP"},
		{"handshake capture", "握手包捕获"},
		{"pmkid", "PMKID 攻击"},
		{"bluetooth", "蓝牙安全"},
		{"ble", "低功耗蓝牙"},
		{"bluejacking", "蓝牙骚扰"},
		{"bluesnarfing", "蓝牙窃取"},
		{"bluebugging", "蓝牙窃听"},
		{"nfc", "NFC 安全"},
		{"rfid", "RFID 安全"},
		{"rfid cloning", "RFID 克隆"},
		{"proxmark", "Proxmark 工具"},
		{"sdr", "软件定义无线电"},
		{"rtl-sdr", "RTL-SDR"},
		{"gnu radio", "GNU Radio"},
		{"signal analysis", "信号分析"},
		{"frequency hopping", "跳频"},
	}
	for _, kw := range wlKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"无线安全: " + kw.hint}
		}
	}
	return nil
}

// tryHardwareSecurityAdvanced 检测硬件安全高级特征。
func tryHardwareSecurityAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	hwKeywords := []struct {
		keyword string
		hint    string
	}{
		{"jtag", "JTAG 调试接口"},
		{"uart", "UART 串口"},
		{"spi", "SPI 协议"},
		{"i2c", "I2C 协议"},
		{"can bus", "CAN 总线"},
		{"openocd", "OpenOCD 调试器"},
		{"bus pirate", "Bus Pirate"},
		{"logic analyzer", "逻辑分析仪"},
		{"oscilloscope", "示波器"},
		{"fpga", "FPGA"},
		{"asic", "ASIC"},
		{"microcontroller", "微控制器"},
		{"arm cortex", "ARM Cortex"},
		{"risc-v", "RISC-V"},
		{"mips", "MIPS 架构"},
		{"power analysis", "功耗分析"},
		{"electromagnetic", "电磁分析"},
		{"fault injection", "故障注入"},
		{"chip whisperer", "ChipWhisperer"},
		{"side channel attack", "侧信道攻击"},
	}
	for _, kw := range hwKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"硬件安全: " + kw.hint}
		}
	}
	return nil
}

// tryBioinformatics 检测生物信息学特征（DNA序列/蛋白质结构）。
func tryBioinformatics(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	bioKeywords := []struct {
		keyword string
		hint    string
	}{
		{"bioinformatics", "生物信息学"},
		{"dna sequence", "DNA 序列"},
		{"rna sequence", "RNA 序列"},
		{"protein structure", "蛋白质结构"},
		{"amino acid", "氨基酸"},
		{"nucleotide", "核苷酸"},
		{"genome", "基因组"},
		{"gene", "基因"},
		{"phylogenetic", "系统发育"},
		{"alignment", "序列比对"},
		{"blast", "BLAST 比对"},
		{"fasta", "FASTA 格式"},
		{"pdb", "PDB 蛋白质结构"},
		{"bio python", "Biopython"},
		{"bioconductor", "Bioconductor"},
		{"crispr", "CRISPR 基因编辑"},
		{"pcr", "PCR 扩增"},
		{"sequencing", "测序"},
		{"polymerase chain", "聚合酶链式反应"},
	}
	for _, kw := range bioKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"生物信息: " + kw.hint}
		}
	}
	return nil
}

// tryGameSecurity 检测游戏安全特征（Unity/Unreal/反作弊/内存修改）。
func tryGameSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	gameKeywords := []struct {
		keyword string
		hint    string
	}{
		{"game hacking", "游戏破解"},
		{"unity", "Unity 引擎"},
		{"unreal engine", "Unreal Engine"},
		{"godot", "Godot 引擎"},
		{"memory editing", "内存修改"},
		{"cheat engine", "Cheat Engine"},
		{"gameguardian", "GameGuardian"},
		{"anti-cheat", "反作弊系统"},
		{"vac", "VAC（Valve 反作弊）"},
		{"battleye", "BattlEye"},
		{"easy anti-cheat", "Easy Anti-Cheat"},
		{"eac", "EAC"},
		{"punkbuster", "PunkBuster"},
		{"speed hack", "加速外挂"},
		{"aimbot", "自瞄外挂"},
		{"wallhack", "透视外挂"},
		{"god mode", "无敌模式"},
		{"noclip", "穿墙模式"},
		{"dll injection", "DLL 注入"},
		{"hook", "Hook 挂钩"},
		{"opcode patch", "操作码补丁"},
		{"game trainer", "游戏修改器"},
	}
	for _, kw := range gameKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"游戏安全: " + kw.hint}
		}
	}
	return nil
}
