// presolve_pwn.go —— Pwn 与逆向类求解器（栈溢出/ROP/符号表/反编译链等）
// 自 presolve.go 机械拆分（31 个声明），内容零改动；数字口径见 scripts/count_stats.py。
package ctfplatform

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// tryGoBinaryStrings 从 Go 二进制/文本中提取常见 Go 特征字符串。
// Go 编译的二进制会保留部分字符串常量（函数名、路径、硬编码值）。
func tryGoBinaryStrings(text string) []string {
	// Go 路径特征
	goPathRe := regexp.MustCompile(`(?i)(main\.go|internal/|cmd/|\.go:\d+|goroutine|panic)`)
	if !goPathRe.MatchString(text) {
		return nil
	}
	// 扫描其中的 flag
	if flags := scanFlags(text); len(flags) > 0 {
		return flags
	}
	// 扫描 base64 编码的 flag
	b64Re := regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)
	for _, m := range b64Re.FindAllString(text, -1) {
		if decoded, err := base64.StdEncoding.DecodeString(padBase64(m)); err == nil {
			if flags := scanFlags(string(decoded)); len(flags) > 0 {
				return flags
			}
		}
	}
	return nil
}

// tryPwnLibcFingerprint 从泄露地址/偏移识别 libc 版本。
// 常见场景：栈泄露的 __libc_start_main+偏移、puts/printf GOT 表泄露。
func tryPwnLibcFingerprint(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	// 匹配十六进制泄露地址（0x7f... 格式，常见 libc 地址特征）
	addrRe := regexp.MustCompile(`0x[0-9a-fA-F]{8,16}`)
	addrs := addrRe.FindAllString(fullText, -1)
	if len(addrs) == 0 {
		return nil
	}
	// 检测 libc 相关关键词
	libcKeywords := []string{"libc", "glibc", "__libc_start_main", "system", "/bin/sh", "puts", "printf", "malloc", "free"}
	lower := strings.ToLower(fullText)
	libcFound := false
	for _, kw := range libcKeywords {
		if strings.Contains(lower, kw) {
			libcFound = true
			break
		}
	}
	if !libcFound {
		return nil
	}
	var results []string
	results = append(results, fmt.Sprintf("检测到 %d 个疑似 libc/堆栈泄露地址，需进一步分析偏移定位版本", len(addrs)))
	// 检测 /bin/sh 字符串（system 调用所需）
	if strings.Contains(fullText, "/bin/sh") || strings.Contains(fullText, "2f62696e2f7368") {
		results = append(results, "检测到 /bin/sh 字符串，可尝试 system('/bin/sh')")
	}
	// 检测 system@plt / system@got 特征
	if strings.Contains(lower, "system@plt") || strings.Contains(lower, "system@got") {
		results = append(results, "检测到 system@plt/GOT 表引用")
	}
	return results
}

// tryPwnExploitPattern 检测常见 pwn 漏洞模式。
func tryPwnExploitPattern(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	type pwnPattern struct {
		keyword string
		hint    string
	}
	patterns := []pwnPattern{
		{"ret2libc", "ret2libc 攻击：利用 libc 函数（system/execve）进行代码执行"},
		{"ret2dlresolve", "ret2dlresolve：利用动态链接器延迟绑定机制执行任意函数"},
		{"rop", "ROP 链构造：利用 gadget 绕过 NX 保护"},
		{"got overwrite", "GOT 表覆写：修改全局偏移表劫持控制流"},
		{"format string", "格式化字符串漏洞：利用 printf 系列读写任意内存"},
		{"buffer overflow", "缓冲区溢出：覆盖返回地址/函数指针"},
		{"use after free", "UAF 漏洞：利用释放后未清空的指针"},
		{"double free", "双重释放：利用 free 链表进行堆利用"},
		{"heap overflow", "堆溢出：覆写堆元数据/相邻对象"},
		{"stack pivot", "栈迁移：利用 leave/ret 控制 RSP"},
		{"one_gadget", "one_gadget：libc 中满足约束条件的 execve('/bin/sh') 地址"},
		{"tcache", "tcache poisoning/binning：利用 glibc tcache 机制"},
		{"seccomp", "沙箱逃逸：seccomp 规则绕过"},
	}
	var results []string
	for _, p := range patterns {
		if strings.Contains(lower, p.keyword) {
			results = append(results, fmt.Sprintf("检测到 '%s'：", p.keyword)+p.hint)
		}
	}
	// 检测 ELF 特征
	if strings.Contains(fullText, "ELF") || strings.Contains(fullText, ".text") || strings.Contains(fullText, ".got") {
		results = append(results, "检测到 ELF 二进制特征，建议使用 pwntools/checksec 分析保护机制")
	}
	if len(results) > 0 {
		return results
	}
	return nil
}

// tryReverseKeywords 检测逆向分析特征（angr/ELF/反混淆/pyc/JS）。
func tryReverseKeywords(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	// angr 特征
	angrKeywords := []struct {
		keyword string
		hint    string
	}{
		{"angr", "angr 二进制分析框架（符号执行/约束求解）"},
		{"symbolic execution", "符号执行：探索所有执行路径"},
		{"claripy", "Claripy：angr 约束求解引擎"},
		{"simprocedure", "SimProcedure：angr 函数模拟"},
		{"state exploration", "状态空间探索"},
		{"path exploration", "路径空间探索"},
	}
	for _, kw := range angrKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "逆向特征: "+kw.hint)
		}
	}

	// ELF/二进制分析特征
	elfKeywords := []struct {
		keyword string
		hint    string
	}{
		{"elf header", "ELF 文件头分析"},
		{"section header", "ELF 节头分析"},
		{"program header", "ELF 程序头分析"},
		{".text", "代码段 .text"},
		{".data", "数据段 .data"},
		{".bss", "BSS 段 .bss"},
		{".got", "全局偏移表 .got"},
		{".plt", "过程链接表 .plt"},
		{".dynsym", "动态符号表 .dynsym"},
		{".rodata", "只读数据段 .rodata（常量字符串）"},
		{"stripped", "已剥离符号的二进制"},
		{"not stripped", "未剥离符号（调试信息保留）"},
		{"nx enabled", "NX/DEP 保护：栈不可执行"},
		{"aslr", "ASLR 地址空间随机化"},
		{"pie enabled", "PIE 地址无关可执行文件"},
		{"canary", "栈保护 Canary 值"},
		{"fortify", "FORTIFY_SOURCE 保护"},
		{"checksec", "checksec 安全特性检测"},
		{"elf64", "64 位 ELF 二进制"},
		{"elf32", "32 位 ELF 二进制"},
	}
	for _, kw := range elfKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "逆向特征: "+kw.hint)
		}
	}

	// 反混淆关键词
	obfuscKeywords := []struct {
		keyword string
		hint    string
	}{
		{"obfuscation", "代码混淆"},
		{"obfuscated", "已混淆代码"},
		{"deobfuscation", "反混淆"},
		{"control flow", "控制流混淆"},
		{"opaque predicate", "不透明谓词混淆"},
		{"dead code", "死代码注入"},
		{"string encryption", "字符串加密"},
		{"anti-debug", "反调试技术"},
		{"anti-vm", "反虚拟机技术"},
		{"packing", "加壳保护"},
		{"upx", "UPX 壳"},
		{"vmprotect", "VMProtect 虚拟化保护"},
		{"themida", "Themida 加壳保护"},
		{"ollvm", "OLLVM 混淆编译器"},
	}
	for _, kw := range obfuscKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "反混淆特征: "+kw.hint)
		}
	}

	// pyc 反编译特征
	pycKeywords := []struct {
		keyword string
		hint    string
	}{
		{".pyc", "Python 字节码文件"},
		{"uncompyle", "uncompyle6：Python 反编译工具"},
		{"decompile", "反编译"},
		{"python bytecode", "Python 字节码"},
		{"marshal", "Python marshal 序列化"},
		{"dis.dis", "Python dis 模块反汇编"},
		{"co_code", "Python 代码对象字节码"},
		{"pyinstaller", "PyInstaller 打包（可能含明文 Python 脚本）"},
		{"py2exe", "py2exe 打包"},
		{"nuitka", "Nuitka 编译"},
	}
	for _, kw := range pycKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "Py逆向特征: "+kw.hint)
		}
	}

	// JS 分析特征
	jsKeywords := []struct {
		keyword string
		hint    string
	}{
		{"javascript", "JavaScript 代码分析"},
		{"eval(", "eval() 动态执行"},
		{"atob(", "atob() Base64 解码"},
		{"btoa(", "btoa() Base64 编码"},
		{"obfuscator.io", "javascript-obfuscator 混淆"},
		{"jsfuck", "JSFuck 混淆"},
		{"aaencode", "aaencode 混淆"},
		{"jjencode", "jjencode 混淆"},
		{"packer", "Packer JS 压缩/混淆"},
		{"webpack", "Webpack 打包"},
		{"source map", "Source Map 调试映射"},
		{"node_modules", "Node.js 依赖"},
		{"console.log", "Console.log 调试输出"},
		{"debugger", "Debugger 断点调试"},
	}
	for _, kw := range jsKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "JS逆向特征: "+kw.hint)
		}
	}

	// APK/移动端特征
	apkKeywords := []struct {
		keyword string
		hint    string
	}{
		{"apk", "Android APK 分析"},
		{"smali", "Smali 反汇编（Android DEX）"},
		{"dex", "DEX 字节码"},
		{"apktool", "APKTool 反编译工具"},
		{"jadx", "JADX 反编译工具"},
		{"frida", "Frida 动态插桩"},
		{"xposed", "Xposed 框架"},
		{"manifest.xml", "AndroidManifest.xml"},
		{"class-dump", "iOS class-dump"},
		{"hopper", "Hopper 反汇编器"},
		{"ida pro", "IDA Pro 反汇编器"},
		{"ghidra", "Ghidra 反汇编器"},
		{"radare2", "Radare2 反汇编框架"},
		{"binary ninja", "Binary Ninja 反汇编器"},
	}
	for _, kw := range apkKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "逆向工具特征: "+kw.hint)
		}
	}

	if len(results) > 0 {
		return results
	}
	return nil
}

// tryPwnAdvanced 检测高级 pwn 漏洞利用技术（ret2dlresolve/沙箱逃逸/tcache/堆利用模板）。
func tryPwnAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	// ret2dlresolve 特征
	ret2dlKeywords := []struct {
		keyword string
		hint    string
	}{
		{"ret2dlresolve", "ret2dlresolve：利用动态链接器延迟绑定执行任意函数"},
		{"dl_runtime_resolve", "dl_runtime_resolve：GOT/PLT 动态解析机制"},
		{"link_map", "link_map：动态链接器链表结构"},
		{"_dl_fixup", "_dl_fixup：延迟绑定修复函数"},
		{"fake struct", "伪造结构体：构造 ELF 结构体绕过验证"},
		{"reloc_index", "重定位索引：控制 GOT 表项"},
		{"symtab", "符号表伪造：构造合法符号表项"},
		{"strtab", "字符串表伪造：注入函数名字符串"},
	}
	for _, kw := range ret2dlKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "ret2dlresolve: "+kw.hint)
		}
	}

	// 沙箱逃逸特征
	sandboxKeywords := []struct {
		keyword string
		hint    string
	}{
		{"sandbox escape", "沙箱逃逸：绕过执行限制"},
		{"seccomp", "seccomp：Linux 内核级系统调用过滤"},
		{"bpf", "BPF：Berkeley Packet Filter（seccomp 规则格式）"},
		{"landlock", "Landlock：Linux 内核安全模块"},
		{"apparmor", "AppArmor：Linux 应用安全模块"},
		{"selinux", "SELinux：强制访问控制"},
		{"open_read_write", "沙箱白名单：仅允许 open/read/write 系统调用"},
		{"orw", "ORW（open/read/write）：沙箱逃逸基础手段"},
		{"shellcode", "Shellcode：注入执行的机器码"},
		{"shellcraft", "Shellcraft：pwntools Shellcode 生成器"},
		{"execve", "execve 系统调用：执行程序"},
		{"openat", "openat 系统调用：打开文件"},
		{"sendfile", "sendfile 系统调用：文件传输"},
		{"io_uring", "io_uring：Linux 异步 IO 接口（可能绕过 seccomp）"},
		{"memfd_create", "memfd_create：内存文件描述符（无文件落地执行）"},
		{"pivot_root", "pivot_root：根目录切换逃逸"},
		{"ptrace", "ptrace：进程调试/注入"},
	}
	for _, kw := range sandboxKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "沙箱逃逸: "+kw.hint)
		}
	}

	// tcache/safe-linking 特征
	tcacheKeywords := []struct {
		keyword string
		hint    string
	}{
		{"tcache", "tcache：glibc 线程缓存分配器"},
		{"tcache poisoning", "tcache poisoning：覆写 tcache next 指针"},
		{"tcache perthread", "tcache_perthread_struct：tcache 元数据结构"},
		{"safe linking", "safe-linking：glibc 2.32+ 指针混淆保护"},
		{"safelink", "safe-linking 指针解混淆：ptr >> 12 ^ &ptr"},
		{"mangled pointer", "混淆指针：glibc 2.32+ tcache/fastbin 指针保护"},
		{"fastbin", "fastbin：快速分配链表"},
		{"unsorted bin", "unsorted bin：未排序链表（信息泄露源）"},
		{"large bin", "large bin：大块链表"},
		{"small bin", "small bin：小块链表"},
		{"chunk", "堆块结构：prev_size/size/data"},
		{"malloc", "malloc：内存分配函数"},
		{"free", "free：内存释放函数（可利用点）"},
		{"unlink", "unlink：堆块摘除（FD/BK 链表操作）"},
		{"house of", "House of 系列：经典堆利用技术"},
		{"house of force", "House of Force：top chunk 大小覆盖"},
		{"house of spirit", "House of Spirit：伪造堆块释放"},
		{"house of einherjar", "House of Einherjar：off-by-one 利用"},
		{"house of orange", "House of Orange：不触发 free 的堆溢出利用"},
		{"ptmalloc", "ptmalloc：glibc 内存分配器"},
		{"arena", "arena：内存分配竞技场"},
		{"top chunk", "top chunk：堆顶剩余块"},
		{"prev_size", "prev_size：前一个堆块大小字段"},
		{"size field", "size 字段：堆块大小元数据"},
		{"aaw", "AAW（Arbitrary Write）：任意地址写"},
		{"aar", "AAR（Arbitrary Read）：任意地址读"},
		{"got overwrite", "GOT 表覆写：修改全局偏移表劫持控制流"},
		{"fsop", "FSOP（File Stream Oriented Programming）：文件流利用"},
		{"vtable", "vtable：虚函数表劫持"},
		{"_IO_", "glibc IO 结构体利用"},
		{"_IO_list_all", "_IO_list_all：glibc IO 链表入口"},
		{"exit_handler", "exit handler：程序退出处理函数劫持"},
		{"atexit", "atexit 注册函数利用"},
		{"rtld", "rtld：运行时动态链接器"},
	}
	for _, kw := range tcacheKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "堆利用特征: "+kw.hint)
		}
	}

	// exploit 构建模板检测
	exploitKeywords := []struct {
		keyword string
		hint    string
	}{
		{"pwntools", "Pwntools：CTF 利用开发框架"},
		{"p = remote", "Pwntools 远程连接模板"},
		{"p = process", "Pwntools 本地进程模板"},
		{"cyclic(", "Pwntools 偏移计算工具"},
		{"fit(", "Pwntools Payload 构造"},
		{"flat(", "Pwntools Payload 扁平化构造"},
		{"rop.call", "ROP 链构造"},
		{"rop.raw", "ROP 原始 gadgets"},
		{"ELF(", "Pwntools ELF 加载器"},
		{"DynELF", "Pwntools 动态 ELF 解析器（远程泄露）"},
		{"ret2libc", "ret2libc：利用 libc 函数执行代码"},
		{"ret2csu", "ret2csu：利用 __libc_csu_init gadget"},
		{"ret2dl", "ret2dl：利用延迟绑定执行函数"},
		{"sigreturn", "SROP（Sigreturn Oriented Programming）：信号返回劫持"},
		{"frame faking", "帧伪造：构造虚假栈帧"},
		{"stack pivoting", "栈迁移：控制 RSP 指针"},
		{"partial overwrite", "部分覆写：仅覆写指针低位绕过 ASLR"},
		{"brute force", "暴力破解：地址空间部分随机化时多试几次"},
		{"leak", "地址泄露：泄露运行时地址绕过 ASLR"},
		{"infoleak", "信息泄露漏洞"},
		{"canary leak", "Canary 泄露：泄露栈保护值"},
		{"one gadget", "one_gadget：libc 中满足约束的 execve('/bin/sh') 地址"},
		{"magic gadget", "magic gadget：特殊条件触发的 gadget"},
	}
	for _, kw := range exploitKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "Exploit技术: "+kw.hint)
		}
	}

	if len(results) > 0 {
		return results
	}
	return nil
}

// tryReverseAdvanced 检测高级逆向特征（.NET/Rust/LLVM/IDA脚本）。
func tryReverseAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	revPatterns := []struct {
		keyword string
		hint    string
	}{
		// .NET 反编译
		{".net", ".NET 框架"},
		{"csharp", "C# 程序"},
		{"dotnet", ".NET 运行时"},
		{"ilspy", "ILSpy 反编译工具"},
		{"dnspy", "dnSpy 调试/反编译工具"},
		{"il code", "IL 中间语言代码"},
		{"cil", "CIL 通用中间语言"},
		{"metadata", ".NET 元数据"},
		{"assembly", ".NET 程序集"},
		{"ildasm", "ILDASM 反汇编工具"},
		{"reflector", ".NET Reflector"},
		{"de4dot", ".NET 混淆器脱壳工具"},
		// Rust 特征
		{"rust", "Rust 编译产物"},
		{"cargo", "Cargo 包管理器"},
		{"rustc", "Rust 编译器"},
		{"mangled name", "Rust/C++ 名称修饰"},
		{"panic_unwind", "Rust panic 处理"},
		{"rust_begin_unwind", "Rust 未展开函数"},
		{"result<", "Rust Result 类型"},
		{"option<", "Rust Option 类型"},
		{"unwrap", "Rust unwrap 方法"},
		{"lifetime", "Rust 生命周期"},
		{"borrow", "Rust 借用检查"},
		// LLVM IR
		{"llvm", "LLVM 编译器基础设施"},
		{"ir code", "LLVM 中间表示"},
		{"bitcode", "LLVM 位码"},
		{"opt level", "LLVM 优化级别"},
		{"clang", "Clang 编译器"},
		{"wasm", "WebAssembly"},
		{"emscripten", "Emscripten（C/C++→WebAssembly）"},
		// IDA 脚本特征
		{"ida pro", "IDA Pro 反汇编器"},
		{"ida python", "IDA Python 脚本"},
		{"idapython", "IDA Python 脚本"},
		{"idc script", "IDC 脚本语言"},
		{"ghidra script", "Ghidra 脚本"},
		{"binary ninja", "Binary Ninja 反汇编器"},
		{"rizin", "Rizin 逆向框架"},
		{"cutter", "Cutter（Rizin GUI）"},
		{"snowman", "Snowman 反编译器"},
		{"retdec", "RetDec 反编译器"},
		{"capstone", "Capstone 反汇编引擎"},
		{"keystone", "Keystone 汇编引擎"},
		{"unicorn", "Unicorn 模拟引擎"},
		{"pwninit", "Pwninit 自动化模板工具"},
		{"ropper", "Ropper ROP gadget 查找器"},
		{"one_gadget", "one_gadget 工具（libc execve 地址）"},
		{"libc-database", "libc-database 版本查询"},
	}
	for _, kw := range revPatterns {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "逆向特征: "+kw.hint)
		}
	}

	if len(results) > 0 {
		return results
	}
	return nil
}

// tryPwnKernel 检测内核利用/侧信道/物理攻击特征。
func tryPwnKernel(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	kernelPatterns := []struct {
		keyword string
		hint    string
	}{
		// 内核利用
		{"kernel exploit", "内核漏洞利用"},
		{"kernel panic", "内核崩溃"},
		{"syzkaller", "Syzkaller 内核 fuzzer"},
		{"syzbot", "Syzbot 内核漏洞报告"},
		{"cve-202", "CVE 编号（安全漏洞）"},
		{"privilege escalation", "权限提升"},
		{"local privilege", "本地权限提升"},
		{"root shell", "Root Shell 获取"},
		{"suid", "SUID 二进制利用"},
		{"sudo", "Sudo 提权"},
		{"setuid", "Setuid 位利用"},
		{"ld_preload", "LD_PRELOAD 注入"},
		{"ld.so", "动态链接器利用"},
		{"rpath", "RPATH 注入"},
		{"proc/self", "/proc/self 文件系统"},
		{"mem_write", "/proc/self/mem 写入"},
		{"io_uring", "io_uring 内核接口利用"},
		{"msgsnd", "msgsnd IPC 消息利用"},
		{"add_key", "add_key 系统调用利用"},
		{"userfaultfd", "userfaultfd 竞态利用"},
		{"iovec", "iovec 结构体利用"},
		{"pipe", "Pipe 缓冲区利用"},
		{"shm", "共享内存利用"},
		{"mmap", "mmap 内存映射利用"},
		{"mprotect", "mprotect 权限修改"},
		{"signalfd", "signalfd 信号利用"},
		{"timerfd", "timerfd 定时器利用"},
		{"epoll", "epoll 事件利用"},
		{"binder", "Binder IPC 利用（Android）"},
		// 侧信道
		{"side channel", "侧信道攻击"},
		{"cache timing", "缓存时序攻击"},
		{"spectre", "Spectre 侧信道漏洞"},
		{"meltdown", "Meltdown 侧信道漏洞"},
		{"branch prediction", "分支预测侧信道"},
		{"flush+reload", "Flush+Reload 缓存攻击"},
		{"prime+probe", "Prime+Probe 缓存攻击"},
		{"rowhammer", "Rowhammer DRAM 位翻转"},
		{"fault injection", "故障注入攻击"},
		{"power analysis", "功耗分析"},
		{"electromagnetic", "电磁侧信道"},
		{"acoustic", "声学侧信道"},
		// 物理攻击
		{"jtag", "JTAG 调试接口"},
		{"uart", "UART 串口调试"},
		{"spi", "SPI 协议"},
		{"i2c", "I2C 协议"},
		{"firmware", "固件分析"},
		{"flash dump", "Flash 存储提取"},
		{"logic analyzer", "逻辑分析仪"},
		{"bus pirate", "Bus Pirate 硬件工具"},
		{"chip whisperer", "ChipWhisperer 故障注入"},
		{"tpm", "TPM 可信平台模块"},
		{"secure boot", "安全启动绕过"},
		{"bootloader", "引导加载程序分析"},
	}
	for _, kw := range kernelPatterns {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "高级利用特征: "+kw.hint)
		}
	}

	if len(results) > 0 {
		return results
	}
	return nil
}

// tryGoSymbolTable 检测 Go 二进制符号表特征。
func tryGoSymbolTable(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	goKeywords := []struct {
		keyword string
		hint    string
	}{
		{"gopkg", "Go 包路径"},
		{"runtime.main", "Go runtime 主函数"},
		{"runtime.goexit", "Go 协程退出"},
		{"goroutine", "Go 协程"},
		{"go.buildid", "Go 构建 ID"},
		{"GOOS", "Go 目标操作系统"},
		{"GOARCH", "Go 目标架构"},
		{"golang", "Go 语言特征"},
		{".go:", "Go 源文件引用"},
		{"gdb", "GDB 调试器"},
		{"dlv", "Delve Go 调试器"},
		{"go tool objdump", "Go 反汇编工具"},
	}
	for _, kw := range goKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"Go逆向: " + kw.hint}
		}
	}
	return nil
}

// trySymbolicExecution 检测符号执行/形式验证特征。
func trySymbolicExecution(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	seKeywords := []struct {
		keyword string
		hint    string
	}{
		{"symbolic execution", "符号执行：探索所有路径"},
		{"constraint solving", "约束求解"},
		{"smt solver", "SMT 求解器"},
		{"z3", "Z3 约束求解器"},
		{"klee", "KLEE 符号执行引擎"},
		{"triton", "Triton 符号执行框架"},
		{"manticore", "Manticore 符号执行"},
		{"concolic", "Concolic 执行"},
		{"abstract interpretation", "抽象解释"},
		{"model checking", "模型检测"},
		{"formal verification", "形式验证"},
	}
	for _, kw := range seKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"符号执行: " + kw.hint}
		}
	}
	return nil
}

// tryDynamicAnalysis 检测动态分析特征（调试/插桩/沙箱/扫描工具）。
func tryDynamicAnalysis(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	daKeywords := []struct {
		keyword string
		hint    string
	}{
		{"dynamic analysis", "动态分析"},
		{"sandbox", "沙箱分析"},
		{"cuckoo", "Cuckoo 沙箱"},
		{"any.run", "ANY.RUN 在线沙箱"},
		{"hybrid analysis", "Hybrid Analysis"},
		{"strace", "strace 系统调用追踪"},
		{"ltrace", "ltrace 库函数追踪"},
		{"ftrace", "ftrace 内核追踪"},
		{"instrumentation", "代码插桩"},
		{"hooking", "函数钩取"},
		{"api monitor", "API 监控"},
		{"wireshark", "网络流量捕获"},
		{"tcpdump", "TCP 流量捕获"},
		{"fiddler", "HTTP 代理抓包"},
		{"burp suite", "Burp Suite Web 安全测试"},
		{"owasp zap", "OWASP ZAP Web 安全扫描"},
		{"nikto", "Nikto Web 服务器扫描"},
		{"nmap", "Nmap 网络扫描"},
		{"masscan", "Masscan 大规模端口扫描"},
		{"nuclei", "Nuclei 漏洞扫描"},
	}
	for _, kw := range daKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"动态分析: " + kw.hint}
		}
	}
	return nil
}

// tryObfuscationDetection 检测代码混淆算法特征。
func tryObfuscationDetection(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	obfKeywords := []struct {
		keyword string
		hint    string
	}{
		{"control flow flattening", "控制流平坦化混淆"},
		{"opaque predicate", "不透明谓词混淆"},
		{"dead code injection", "死代码注入"},
		{"string encryption", "字符串加密混淆"},
		{"instruction substitution", "指令替换"},
		{"array flattening", "数组扁平化"},
		{"variable renaming", "变量重命名"},
		{"proxy call", "代理调用"},
		{"virtual machine", "虚拟机保护"},
		{"code virtualization", "代码虚拟化"},
		{"bytecode obfuscation", "字节码混淆"},
		{"source map", "Source Map（可能含原始代码）"},
		{"webpack", "Webpack 打包"},
	}
	for _, kw := range obfKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"混淆检测: " + kw.hint}
		}
	}
	return nil
}

// tryEmulatorDetection 检测模拟器/沙箱检测特征（反调试/反分析）。
func tryEmulatorDetection(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	emuKeywords := []struct {
		keyword string
		hint    string
	}{
		{"anti-debug", "反调试技术"},
		{"anti-vm", "反虚拟机检测"},
		{"anti-sandbox", "反沙箱检测"},
		{"vm detection", "虚拟机检测"},
		{"isdebuggerpresent", "IsDebuggerPresent"},
		{"ptrace", "ptrace 自检"},
		{"timing check", "时间检测"},
		{"cpuid", "CPUID 指令"},
		{"vmware", "VMware 检测"},
		{"virtualbox", "VirtualBox 检测"},
		{"qemu", "QEMU 检测"},
		{"debugger detection", "调试器检测"},
		{"integrity check", "完整性校验"},
		{"crc32", "CRC32 校验"},
	}
	for _, kw := range emuKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"反分析: " + kw.hint}
		}
	}
	return nil
}

// tryCodeVirtualization 检测代码虚拟化保护特征。
func tryCodeVirtualization(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	vmKeywords := []struct {
		keyword string
		hint    string
	}{
		{"vmprotect", "VMProtect 虚拟化保护"},
		{"themida", "Themida 加壳/虚拟化"},
		{"enigma protector", "Enigma Protector"},
		{"upx", "UPX 加壳"},
		{"aspack", "ASPack 加壳"},
		{"virtual machine", "自定义虚拟机"},
		{"bytecode interpreter", "字节码解释器"},
		{"dispatch table", "分发表"},
	}
	for _, kw := range vmKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"虚拟化保护: " + kw.hint}
		}
	}
	return nil
}

// tryObfuscationVariant 检测混淆算法变体（OLLVM/虚拟机壳/DEX混淆）。
func tryObfuscationVariant(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	obfKeywords := []struct {
		keyword string
		hint    string
	}{
		{"ollvm", "OLLVM 混淆编译器"},
		{"obfuscator-llvm", "Obfuscator-LLVM"},
		{"string obfuscation", "字符串混淆"},
		{"control flow", "控制流混淆"},
		{"bogus control flow", "虚假控制流"},
		{"flattening", "控制流平坦化"},
		{"proguard", "ProGuard（Android 混淆）"},
		{"dexguard", "DexGuard"},
		{"dex2jar", "dex2jar"},
		{"jadx", "JADX 反编译"},
		{"apktool", "APKTool"},
		{"smali", "Smali 汇编"},
		{"dalvik", "Dalvik 虚拟机"},
		{"ndk", "Android NDK"},
	}
	for _, kw := range obfKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"混淆变体: " + kw.hint}
		}
	}
	return nil
}

// tryDecompilerChain 检测反编译工具链特征。
func tryDecompilerChain(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	decKeywords := []struct {
		keyword string
		hint    string
	}{
		{"decompiler", "反编译器"},
		{"disassembler", "反汇编器"},
		{"ida pro", "IDA Pro"},
		{"ghidra", "Ghidra"},
		{"binary ninja", "Binary Ninja"},
		{"radare2", "Radare2"},
		{"rizin", "Rizin"},
		{"angr", "angr 符号执行"},
		{"capstone", "Capstone 反汇编"},
		{"keystone", "Keystone 汇编"},
		{"unicorn", "Unicorn 模拟器"},
		{"frida", "Frida 动态插桩"},
		{"gdb", "GDB 调试器"},
		{"lldb", "LLDB 调试器"},
		{"windbg", "WinDbg"},
		{"x64dbg", "x64dbg"},
		{"ollydbg", "OllyDbg"},
		{"pwntools", "Pwntools"},
		{"one_gadget", "one_gadget"},
	}
	for _, kw := range decKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"逆向工具链: " + kw.hint}
		}
	}
	return nil
}

// tryIOFileExploit 检测 IO_FILE/FSOP 利用特征。
func tryIOFileExploit(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	ioKeywords := []struct {
		keyword string
		hint    string
	}{
		{"io_file", "IO_FILE 结构体利用"},
		{"_io_list_all", "_IO_list_all"},
		{"fsop", "FSOP（File Stream Oriented Programming）"},
		{"fake file stream", "伪造文件流"},
		{"vtable hijacking", "vtable 劫持"},
		{"house of apple", "House of Apple"},
		{"house of banana", "House of Banana"},
		{"house of cat", "House of Cat"},
		{"house of orange", "House of Orange"},
		{"house of spirit", "House of Spirit"},
		{"house of force", "House of Force"},
		{"got overwrite", "GOT 表覆写"},
		{"ret2dlresolve", "ret2dlresolve"},
		{"lazy binding", "延迟绑定"},
	}
	for _, kw := range ioKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"IO_FILE/FSOP: " + kw.hint}
		}
	}
	return nil
}

// tryHeapSpray 检测堆喷射/格式化字符串漏洞特征。
func tryHeapSpray(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	heapKeywords := []struct {
		keyword string
		hint    string
	}{
		{"heap spray", "堆喷射"},
		{"format string", "格式化字符串漏洞"},
		{"format string attack", "格式化字符串攻击"},
		{"printf vulnerability", "printf 漏洞"},
		{"%n", "格式化字符串 %n 写入"},
		{"%x", "格式化字符串 %x 泄露"},
		{"stack pivot", "栈迁移"},
		{"stack smash", "栈溢出"},
		{"return address", "返回地址覆写"},
		{"canary bypass", "Canary 绕过"},
		{"information leak", "信息泄露"},
		{"partial overwrite", "部分覆写"},
		{"one gadget", "one_gadget"},
		{"ret2libc", "ret2libc"},
		{"rop chain", "ROP 链"},
		{"jop", "JOP（Jump-Oriented Programming）"},
		{"cop", "COP（Call-Oriented Programming）"},
	}
	for _, kw := range heapKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"Pwn利用: " + kw.hint}
		}
	}
	return nil
}

// tryGoReverseAdvanced 检测 Go 语言逆向高级特征。

// ── 补全：缺失函数 ──────────────────────────────────────

// ── P5 批次：reverse + pwn 高级（从 execution.go 迁回 pwn.go，消除 registry 调度处的重复声明/未定义）──

func tryGoReverseAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"go reverse", "Go逆向"}, {"goretk", "goretk工具"}, {"redress", "redress工具"},
		{"pclntab", "Go程序计数器行号表"}, {"gopclntab", "gopclntab"}, {"runtime.main", "Go runtime主函数"},
		{"runtime.goexit", "Go协程退出"}, {"type descriptor", "Go类型描述符"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) {
			return []string{"Go逆向: " + kw.h}
		}
	}
	return nil
}

func tryPythonReverseAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"pyinstaller", "PyInstaller打包"}, {"py2exe", "py2exe打包"}, {"nuitka", "Nuitka编译"},
		{"uncompyle6", "uncompyle6反编译"}, {"decompyle3", "decompyle3反编译"}, {"pycdc", "pycdc反编译"},
		{"marshal", "marshal序列化"}, {"co_code", "Python字节码"}, {".pyc", "Python编译文件"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) {
			return []string{"Python逆向: " + kw.h}
		}
	}
	return nil
}

func tryDotNetReverseAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"csharp", "C#程序"}, {"ilspy", "ILSpy反编译"}, {"dnspy", "dnSpy调试/反编译"},
		{"il code", "IL中间代码"}, {"cil", "通用中间语言"}, {"ildasm", "ILDASM反汇编"},
		{"de4dot", ".NET混淆器脱壳"}, {"assembly", ".NET程序集"}, {"managed code", "托管代码"}, {"pinvoke", "P/Invoke调用"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) {
			return []string{".NET逆向: " + kw.h}
		}
	}
	return nil
}

func tryFormatStringArbitraryWrite(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"format string arbitrary write", "格式化字符串任意写"}, {"%n write", "%n写入"},
		{"%hn write", "%hn写入（两字节）"}, {"%hhn write", "%hhn写入（单字节）"},
		{"got overwrite", "GOT表覆写"}, {"global offset table", "全局偏移表"},
		{"format string leak", "格式化字符串泄露"}, {"stack leak", "栈泄露"},
		{"canary leak", "Canary泄露"}, {"libc leak", "libc泄露"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) {
			return []string{"格式化字符串: " + kw.h}
		}
	}
	return nil
}

func tryRet2csu(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"ret2csu", "ret2csu利用"}, {"__libc_csu_init", "__libc_csu_init gadget"},
		{"pop gadget", "POP gadget"}, {"ret gadget", "RET gadget"}, {"syscall gadget", "syscall gadget"},
		{"rop chain", "ROP链"}, {"rop gadget", "ROP gadget"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) {
			return []string{"ret2csu: " + kw.h}
		}
	}
	return nil
}

func tryRet2Syscall(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"ret2syscall", "ret2syscall利用"}, {"execve", "execve系统调用"},
		{"open", "open系统调用"}, {"read", "read系统调用"}, {"write", "write系统调用"},
		{"mmap", "mmap系统调用"}, {"mprotect", "mprotect系统调用"}, {"dup2", "dup2系统调用"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) {
			return []string{"ret2syscall: " + kw.h}
		}
	}
	return nil
}

func tryStackOverflow(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"buffer overflow", "缓冲区溢出"}, {"stack overflow", "栈溢出"}, {"heap overflow", "堆溢出"},
		{"integer overflow", "整数溢出"}, {"off-by-one", "Off-by-one溢出"},
		{"strcpy", "strcpy不安全函数"}, {"gets", "gets不安全函数"}, {"sprintf", "sprintf不安全函数"},
		{"canary", "栈保护Canary"}, {"nx bit", "NX位（不可执行栈）"}, {"aslr", "ASLR地址随机化"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) {
			return []string{"栈溢出: " + kw.h}
		}
	}
	return nil
}

func tryHypervisorEscape(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments { fullText += "\n" + v }
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"hypervisor escape", "虚拟机逃逸"}, {"vm escape", "VM逃逸"}, {"vmware escape", "VMware逃逸"},
		{"virtualbox escape", "VBox逃逸"}, {"qemu escape", "QEMU逃逸"}, {"docker escape", "Docker逃逸"},
		{"container breakout", "容器突破"}, {"sandbox escape", "沙箱逃逸"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) { return []string{"虚拟化逃逸: " + kw.h} }
	}
	return nil
}

func tryFirmwareExploit(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments { fullText += "\n" + v }
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"firmware", "固件"}, {"bios", "BIOS"}, {"uefi", "UEFI"}, {"bootkit", "Bootkit"},
		{"rootkit", "Rootkit"}, {"secure boot", "安全启动绕过"}, {"tpm attack", "TPM攻击"},
		{"supply chain", "供应链攻击"}, {"jtag", "JTAG"}, {"uart", "UART"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) { return []string{"固件利用: " + kw.h} }
	}
	return nil
}

func tryOSKernelSecurity(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments { fullText += "\n" + v }
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"windows kernel", "Windows内核"}, {"linux kernel", "Linux内核"}, {"kernel exploit", "内核漏洞"},
		{"syscall", "系统调用"}, {"rootkit", "Rootkit"}, {"aslr", "ASLR"}, {"dep", "DEP"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) { return []string{"内核安全: " + kw.h} }
	}
	return nil
}

// ── 补全：被去重误删的函数 ──────────────────────────────────

func tryGoReverseAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments { fullText += "\n" + v }
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"go reverse", "Go逆向"}, {"goretk", "goretk"}, {"redress", "redress"},
		{"pclntab", "pclntab"}, {"gopclntab", "gopclntab"}, {"runtime.main", "runtime.main"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) { return []string{"Go逆向: " + kw.h} }
	}
	return nil
}

func tryPythonReverseAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments { fullText += "\n" + v }
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"pyinstaller", "PyInstaller"}, {"py2exe", "py2exe"}, {"nuitka", "Nuitka"},
		{"uncompyle6", "uncompyle6"}, {"decompyle3", "decompyle3"}, {"marshal", "marshal"},
		{"co_code", "字节码"}, {".pyc", ".pyc"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) { return []string{"Python逆向: " + kw.h} }
	}
	return nil
}

func tryDotNetReverseAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments { fullText += "\n" + v }
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"csharp", "C#"}, {"ilspy", "ILSpy"}, {"dnspy", "dnSpy"},
		{"il code", "IL代码"}, {"cil", "CIL"}, {"ildasm", "ILDASM"},
		{"de4dot", "de4dot"}, {"assembly", ".NET程序集"}, {"managed code", "托管代码"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) { return []string{".NET逆向: " + kw.h} }
	}
	return nil
}

func tryRet2csu(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments { fullText += "\n" + v }
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"ret2csu", "ret2csu"}, {"__libc_csu_init", "__libc_csu_init gadget"},
		{"rop chain", "ROP链"}, {"rop gadget", "ROP gadget"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) { return []string{"ret2csu: " + kw.h} }
	}
	return nil
}

func tryFormatStringArbitraryWrite(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments { fullText += "\n" + v }
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"format string", "格式化字符串"}, {"%n write", "%n写入"},
		{"got overwrite", "GOT表覆写"}, {"stack leak", "栈泄露"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) { return []string{"格式化字符串: " + kw.h} }
	}
	return nil
}

func tryStackOverflow(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments { fullText += "\n" + v }
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"buffer overflow", "缓冲区溢出"}, {"stack overflow", "栈溢出"},
		{"off-by-one", "Off-by-one"}, {"canary", "Canary"}, {"aslr", "ASLR"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) { return []string{"栈溢出: " + kw.h} }
	}
	return nil
}

func tryRet2Syscall(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments { fullText += "\n" + v }
	lower := strings.ToLower(fullText)
	kws := []struct{ k, h string }{
		{"ret2syscall", "ret2syscall"}, {"execve", "execve"},
		{"open", "open系统调用"}, {"read", "read系统调用"}, {"write", "write系统调用"},
		{"mmap", "mmap"}, {"mprotect", "mprotect"}, {"dup2", "dup2"},
	}
	for _, kw := range kws {
		if strings.Contains(lower, kw.k) { return []string{"ret2syscall: " + kw.h} }
	}
	return nil
}
