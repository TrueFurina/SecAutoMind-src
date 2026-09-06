// presolve_forensics.go —— 取证与隐写类求解器（隐写/磁盘/EXIF/魔数/熵分析等）
// 自 presolve.go 机械拆分（14 个声明），内容零改动；数字口径见 scripts/count_stats.py。
package ctfplatform

import (
	"regexp"
	"strings"
)

// tryStringsFlagScan 对文本/附件做 strings 扫描（提取可打印字符串中的 flag）。
// 模拟 Linux strings 命令 + flag 正则扫描。
func tryStringsFlagScan(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	// 提取连续可打印字符串（长度≥6）
	stringsRe := regexp.MustCompile(`[\x20-\x7E]{6,}`)
	matches := stringsRe.FindAllString(fullText, -1)
	for _, m := range matches {
		if flags := scanFlags(m); len(flags) > 0 {
			return flags
		}
	}
	return nil
}

// tryHardcodedSecrets 扫描硬编码凭证/敏感信息（API key/password/token）。
func tryHardcodedSecrets(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	// flag 在密钥/密码字段中
	secretRe := regexp.MustCompile(`(?i)(?:password|passwd|secret|token|api[_-]?key|flag)\s*[=:]\s*["']?([^\s"'<>]{8,})["']?`)
	for _, m := range secretRe.FindAllStringSubmatch(fullText, -1) {
		if len(m) > 1 {
			val := m[1]
			if flags := scanFlags(val); len(flags) > 0 {
				return flags
			}
			// 值本身可能是 flag（无前缀）
			if len(val) >= 8 && len(val) <= 64 {
				return []string{"硬编码凭证: " + val}
			}
		}
	}
	return nil
}

// tryStegoDetect 检测隐写术特征（JPEG/PNG 嵌入、LSB、文件尾附加）。
func tryStegoDetect(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	// 关键词检测
	stegoKeywords := []struct {
		keyword string
		hint    string
	}{
		{"steganography", "隐写术：数据隐藏在图片/音频/视频中"},
		{"steg", "Steg 工具：常见隐写检测工具"},
		{"stegsolve", "StegSolve：图片隐写分析工具（通道分离/位平面分析）"},
		{"lsb", "LSB 隐写：最低有效位隐写，修改像素最低位嵌入数据"},
		{"steghide", "StegHide：图片/音频隐写工具（JPEG/BMP/WAV）"},
		{"zsteg", "zsteg：PNG/BMP 隐写自动检测工具"},
		{"exiftool", "ExifTool：图片元数据分析（可能含隐藏信息）"},
		{"binwalk", "Binwalk：固件/文件分析（检测文件中嵌入的文件）"},
		{"foremost", "Foremost：文件恢复/提取工具"},
		{"strings", "strings 命令：提取二进制文件中的可打印字符串"},
		{"file signature", "文件签名分析：检测文件头/尾异常"},
		{"trailing data", "文件尾附加数据：图片文件尾部附加了额外数据"},
		{"magic bytes", "魔数检测：文件头魔数与扩展名不匹配"},
	}
	for _, kw := range stegoKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "隐写特征: "+kw.hint)
		}
	}
	if len(results) > 0 {
		return results
	}

	// 检测疑似嵌入文件的 hex 特征（PNG/JPEG 文件头嵌入）
	if strings.Contains(lower, "89504e47") || strings.Contains(lower, "ffd8ffe0") || strings.Contains(lower, "ffd8ffe1") {
		return []string{"检测到图片文件头魔数（PNG/JPEG），可能有嵌入文件或隐写"}
	}
	return nil
}

// tryTrafficAnalysis 检测流量分析特征（pcap 文件关键词、协议分析）。
func tryTrafficAnalysis(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	trafficKeywords := []struct {
		keyword string
		hint    string
	}{
		{"pcap", "PCAP 流量包分析：网络数据包捕获分析"},
		{"wireshark", "Wireshark：网络协议分析工具"},
		{"tshark", "tshark：命令行流量分析工具"},
		{"tcp.stream", "TCP 流重组：跟踪单个 TCP 连接的数据流"},
		{"http.request", "HTTP 请求分析：提取 Web 请求中的数据"},
		{"dns", "DNS 查询分析：DNS 请求/响应中可能隐藏数据"},
		{"ftp-data", "FTP 数据传输：FTP 数据通道可能泄露文件"},
		{"smtp", "SMTP 邮件分析：邮件传输中的附件/内容"},
		{"icmp", "ICMP 隧道：利用 ICMP 包传输隐蔽数据"},
		{"base64.*http", "HTTP 中的 Base64 编码数据"},
		{"cookie", "Cookie 注入：利用 HTTP Cookie 传输数据"},
		{"user-agent", "User-Agent 异常：UA 头中可能隐藏数据"},
		{"covert channel", "隐蔽通道：利用合法协议传输隐蔽数据"},
	}
	for _, kw := range trafficKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "流量特征: "+kw.hint)
		}
	}
	if len(results) > 0 {
		return results
	}
	return nil
}

// tryDiskForensics 检测磁盘取证特征（文件系统/分区/取证工具关键词）。
func tryDiskForensics(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	var results []string

	forensicsKeywords := []struct {
		keyword string
		hint    string
	}{
		{"disk image", "磁盘镜像：原始磁盘/分区镜像分析"},
		{"autopsy", "Autopsy：数字取证分析平台"},
		{"volatility", "Volatility：内存取证分析框架"},
		{"ftk", "FTK：取证工具包"},
		{"sleuth kit", "The Sleuth Kit：文件系统取证分析"},
		{"ntfs", "NTFS 文件系统分析"},
		{"ext4", "EXT4 文件系统分析"},
		{"fat32", "FAT32 文件系统分析"},
		{"partition", "分区表分析：MBR/GPT 分区结构"},
		{"inode", "inode 分析：Linux 文件系统元数据"},
		{"slack space", "文件松弛空间：文件未使用空间可能隐藏数据"},
		{"deleted file", "已删除文件恢复"},
		{"registry", "Windows 注册表取证"},
		{"event log", "Windows 事件日志分析"},
		{"prefetch", "Windows Prefetch 文件分析"},
		{"mft", "MFT（主文件表）分析：NTFS 文件系统元数据"},
		{"recycle.bin", "回收站分析：$Recycle.Bin 中的删除记录"},
	}
	for _, kw := range forensicsKeywords {
		if strings.Contains(lower, kw.keyword) {
			results = append(results, "取证特征: "+kw.hint)
		}
	}
	if len(results) > 0 {
		return results
	}
	return nil
}

// tryZipChain 检测 ZIP 链式解压（压缩包套娃、嵌套 ZIP）。
func tryZipChain(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)

	zipKeywords := []struct {
		keyword string
		hint    string
	}{
		{"nested zip", "嵌套 ZIP：ZIP 文件内包含 ZIP 文件（套娃）"},
		{"zip bomb", "ZIP 炸弹：极小压缩包解压后极大"},
		{"zip slip", "Zip Slip 漏洞：路径遍历写入任意位置"},
		{"compressed archive", "压缩归档：可能含多层嵌套"},
	}
	for _, kw := range zipKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"ZIP 特征: " + kw.hint}
		}
	}
	// 检测多层压缩提示
	if strings.Contains(lower, "zip") && strings.Contains(lower, "extract") {
		return []string{"检测到 ZIP 解压关键词，可能存在多层嵌套或伪加密"}
	}
	return nil
}

// tryGridResample 检测网格重采样关键词（图片隐写高级技术）。
func tryGridResample(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	gridKeywords := []struct {
		keyword string
		hint    string
	}{
		{"grid resample", "网格重采样隐写（像素网格偏移嵌入数据）"},
		{"pixel manipulation", "像素级操作"},
		{"color channel", "颜色通道分离"},
		{"rgb", "RGB 颜色空间"},
		{"hsv", "HSV 颜色空间"},
		{"yuv", "YUV 颜色空间"},
		{"chroma", "色度通道"},
		{"luminance", "亮度通道"},
		{"bit plane", "位平面分析"},
		{"lsb steganography", "LSB 隐写术"},
		{"image forensics", "图片取证"},
		{"error level analysis", "ELA 错误级别分析"},
		{"noise analysis", "噪声分析"},
		{"frequency domain", "频域分析"},
		{"dct", "离散余弦变换（DCT）"},
		{"fft", "快速傅里叶变换（FFT）"},
	}
	for _, kw := range gridKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"隐写分析: " + kw.hint}
		}
	}
	return nil
}

// tryFilenameChain 检测文件名链解码（文件名本身含编码/加密信息）。
func tryFilenameChain(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	chainKeywords := []struct {
		keyword string
		hint    string
	}{
		{"filename", "文件名分析"},
		{"extension", "文件扩展名分析"},
		{"magic number", "文件魔数分析"},
		{"file header", "文件头分析"},
		{"file signature", "文件签名"},
		{"hex dump", "十六进制转储"},
		{"xxd", "xxd 十六进制查看器"},
		{"file command", "file 命令识别文件类型"},
	}
	for _, kw := range chainKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"文件分析: " + kw.hint}
		}
	}
	return nil
}

// tryEntropyAnalysis 检测熵分析特征（高熵字符串=加密/编码/压缩）。
func tryEntropyAnalysis(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	entKeywords := []struct {
		keyword string
		hint    string
	}{
		{"entropy", "熵分析：测量数据随机性"},
		{"shannon entropy", "香农熵：信息熵计算"},
		{"high entropy", "高熵数据：可能加密/编码/压缩"},
		{"low entropy", "低熵数据：可能明文/重复"},
		{"randomness", "随机性分析"},
		{"compression", "数据压缩"},
		{"encryption", "数据加密"},
		{"encoded data", "编码数据"},
		{"hex dump", "十六进制转储"},
		{"binary analysis", "二进制分析"},
	}
	for _, kw := range entKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"熵分析: " + kw.hint}
		}
	}
	return nil
}

// tryEXIFMetadata 检测图片 EXIF 元数据特征（GPS/相机/编辑痕迹）。
func tryEXIFMetadata(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	exifKeywords := []struct {
		keyword string
		hint    string
	}{
		{"exif", "EXIF 元数据"},
		{"gps", "GPS 定位信息"},
		{"latitude", "纬度"},
		{"longitude", "经度"},
		{"camera", "相机信息"},
		{"make", "设备制造商"},
		{"model", "设备型号"},
		{"software", "编辑软件"},
		{"datetime", "拍摄时间"},
		{"thumbnail", "缩略图"},
		{"iptc", "IPTC 元数据"},
		{"xmp", "XMP 元数据"},
		{"metadata", "元数据"},
		{"geolocation", "地理定位"},
	}
	for _, kw := range exifKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"EXIF取证: " + kw.hint}
		}
	}
	return nil
}

// tryAudioStego 检测音频隐写特征（频谱分析/LSB/回声隐藏）。
func tryAudioStego(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	audioKeywords := []struct {
		keyword string
		hint    string
	}{
		{"audio steganography", "音频隐写"},
		{"spectrogram", "频谱图"},
		{"frequency domain", "频域分析"},
		{"echo hiding", "回声隐藏"},
		{"lsb audio", "音频 LSB 隐写"},
		{"phase coding", "相位编码"},
		{"spread spectrum", "扩频隐写"},
		{"tone insertion", "音调插入"},
		{"wav", "WAV 音频"},
		{"mp3", "MP3 音频"},
		{"flac", "FLAC 音频"},
		{"ogg", "OGG 音频"},
		{"waveform", "波形分析"},
		{"audacity", "Audacity 音频编辑"},
	}
	for _, kw := range audioKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"音频隐写: " + kw.hint}
		}
	}
	return nil
}

// tryMagicBytes 检测文件魔术字节（文件头/尾/签名识别）。
func tryMagicBytes(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	magicKeywords := []struct {
		keyword string
		hint    string
	}{
		{"magic bytes", "文件魔术字节"},
		{"file signature", "文件签名"},
		{"file header", "文件头"},
		{"89504e47", "PNG 文件头"},
		{"ffd8ff", "JPEG 文件头"},
		{"47494638", "GIF 文件头"},
		{"504b0304", "ZIP 文件头"},
		{"25504446", "PDF 文件头"},
		{"7f454c46", "ELF 文件头"},
		{"4d5a", "PE/EXE 文件头"},
		{"cafebabe", "Java Class 文件头"},
		{"52617221", "RAR 文件头"},
		{"1f8b08", "GZIP 文件头"},
		{"425a68", "BZ2 文件头"},
		{"377abcaf271c", "7Z 文件头"},
		{"hex dump", "十六进制转储"},
		{"binwalk", "Binwalk 文件分析"},
	}
	for _, kw := range magicKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"文件签名: " + kw.hint}
		}
	}
	return nil
}

// tryDigitalForensicsAdvanced 检测数字取证高级特征（内存取证/网络取证/日志分析）。
func tryDigitalForensicsAdvanced(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	dfKeywords := []struct {
		keyword string
		hint    string
	}{
		{"digital forensics", "数字取证"},
		{"memory forensics", "内存取证"},
		{"volatility", "Volatility 内存取证"},
		{"rekall", "Rekall 内存取证"},
		{"network forensics", "网络取证"},
		{"packet capture", "数据包捕获"},
		{"pcap analysis", "PCAP 分析"},
		{"wireshark", "Wireshark"},
		{"zeek", "Zeek（Bro）网络安全监控"},
		{"suricata", "Suricata IDS"},
		{"snort", "Snort IDS"},
		{"log analysis", "日志分析"},
		{"siem", "SIEM 安全信息和事件管理"},
		{"splunk", "Splunk"},
		{"elk stack", "ELK Stack"},
		{"elasticsearch", "Elasticsearch"},
		{"timeline analysis", "时间线分析"},
		{"artifact analysis", "工件分析"},
		{"evidence preservation", "证据保全"},
		{"chain of custody", "监管链"},
		{"forensic imaging", "取证镜像"},
		{"write blocker", "写保护器"},
	}
	for _, kw := range dfKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"数字取证: " + kw.hint}
		}
	}
	return nil
}

// tryNetworkForensics 检测网络取证特征（PCAP分析/流量还原/协议解析）。
func tryNetworkForensics(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}
	lower := strings.ToLower(fullText)
	netKeywords := []struct {
		keyword string
		hint    string
	}{
		{"pcap", "PCAP 流量捕获"},
		{"pcapng", "PCAPNG 流量捕获"},
		{"tcpdump", "tcpdump 流量捕获"},
		{"wireshark", "Wireshark 协议分析"},
		{"tshark", "tshark 命令行分析"},
		{"zeek", "Zeek（Bro）网络安全监控"},
		{"suricata", "Suricata IDS"},
		{"snort", "Snort IDS"},
		{"network forensics", "网络取证"},
		{"packet analysis", "数据包分析"},
		{"flow analysis", "流量分析"},
		{"conversation analysis", "会话分析"},
		{"protocol dissection", "协议解析"},
		{"http analysis", "HTTP 流量分析"},
		{"dns analysis", "DNS 流量分析"},
		{"tls decryption", "TLS 流量解密"},
		{"ssl decryption", "SSL 流量解密"},
		{"key log file", "SSL Key Log 文件"},
		{"master secret", "主密钥"},
		{"pre-master secret", "预主密钥"},
		{"network tap", "网络分流器"},
		{"packet capture", "数据包捕获"},
		{"traffic mirroring", "流量镜像"},
	}
	for _, kw := range netKeywords {
		if strings.Contains(lower, kw.keyword) {
			return []string{"网络取证: " + kw.hint}
		}
	}
	return nil
}
