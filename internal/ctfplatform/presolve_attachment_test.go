package ctfplatform

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// TestPresolveLoadsChatUploadedAttachment 端到端验证 Tier 2 激活：
// 生产 handler 传 nil attachments，但聊天上传文件的绝对路径已拼在消息文本里。
// 本测试模拟真实上传场景（二进制附件写入 chat_uploads），验证 Presolve 能
// 读回真实内容并由执行层/文本求解器提取 flag —— 即 exec_* 不再是休眠态。
func TestPresolveLoadsChatUploadedAttachment(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Skipf("无法获取工作目录: %v", err)
	}
	dir := filepath.Join(cwd, "chat_uploads", "2026-09-07", "test-presolve-attach")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("无法创建测试附件目录: %v", err)
	}
	defer os.RemoveAll(filepath.Join(cwd, "chat_uploads", "2026-09-07", "test-presolve-attach"))

	// 模拟真实 CTF 二进制附件：flag 藏在前后的不可打印字节之间（strings 场景）
	payload := append([]byte{0x00, 0x01, 0x02, 'j', 'u', 'n', 'k', 0x00},
		[]byte("flag{upl04d_4tt4chm3nt_r34l}")...)
	payload = append(payload, 0x00, 0x7f, 0x80)
	attPath := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(attPath, payload, 0o644); err != nil {
		t.Skipf("无法写入测试附件: %v", err)
	}

	desc := "附件是一个二进制文件，flag 藏在里面，自己分析吧。\n\n" +
		attachmentMarker + "\n- payload.bin: " + attPath

	pr := NewPresolver(zap.NewNop())
	res := pr.Presolve(context.Background(), &Challenge{
		Description: desc,
		Category:    "misc",
	}, nil) // ← 关键：attachments 传 nil，完全复刻生产 handler 的调用方式

	if !res.Solved {
		t.Fatalf("期望命中（附件内容应被载入并解出 flag），实际未命中: %s", res.Detail)
	}
	joined := strings.Join(res.Flags, " ")
	if !strings.Contains(joined, "upl04d_4tt4chm3nt_r34l") {
		t.Fatalf("未从上传附件中提取到目标 flag，实际 flags=%v", res.Flags)
	}
	t.Logf("✅ 上传附件激活成功：engine=%s flags=%v", res.Engine, res.Flags)
}

// TestExecSolverConsumesUploadedPcap 专项证明「exec_* 本身」被激活：
// 上面的集成测试命中引擎是 base64_multilayer（优先级更高），只证明附件内容
// 进了求解池；这里用只有 exec_pcap_http 能解的 pcap，直接断言该执行层求解器
// 从「上传附件」中还原出 flag，坐实 exec_* 不再是休眠态。
func TestExecSolverConsumesUploadedPcap(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Skipf("无法获取工作目录: %v", err)
	}
	dir := filepath.Join(cwd, "chat_uploads", "2026-09-07", "test-presolve-pcap")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("无法创建测试附件目录: %v", err)
	}
	defer os.RemoveAll(filepath.Join(cwd, "chat_uploads", "2026-09-07", "test-presolve-pcap"))

	pcapPath := filepath.Join(dir, "traffic.pcap")
	if err := os.WriteFile(pcapPath, buildTestPcap("flag{upl04ded_pc4p_r34l}"), 0o644); err != nil {
		t.Skipf("无法写入 pcap 测试附件: %v", err)
	}

	desc := "抓了个包，flag 应该在 HTTP 请求里。\n\n" +
		attachmentMarker + "\n- traffic.pcap: " + pcapPath

	// 复刻生产调用：attachments 传 nil，由 Presolve 自行从文本载入上传附件
	pr := NewPresolver(zap.NewNop())
	ch := &Challenge{Description: desc, Category: "misc"}
	res := pr.Presolve(context.Background(), ch, nil)
	if !res.Solved || !strings.Contains(strings.Join(res.Flags, " "), "upl04ded_pc4p_r34l") {
		t.Fatalf("Presolve 未能从上传 pcap 解出 flag: solved=%v flags=%v", res.Solved, res.Flags)
	}

	// 直接断言执行层求解器本身能吃到附件内容（不依赖哪个引擎胜出）
	loaded := loadChatAttachmentFiles(desc, zap.NewNop())
	if len(loaded) == 0 {
		t.Fatalf("loadChatAttachmentFiles 未载入任何附件")
	}
	got := tryExecPcapHTTP(context.Background(), "", loaded)
	if len(got) == 0 || !strings.Contains(got[0], "upl04ded_pc4p_r34l") {
		t.Fatalf("exec_pcap_http 未从上传附件还原 flag，got=%v", got)
	}
	t.Logf("✅ exec_pcap_http 从上传附件解题成功: %v（Presolve engine=%s）", got, res.Engine)
}

// buildTestPcap 构造最小可解析 pcap（magic 0xa1b2c3d4 + 24B 全局头 +
// 16B 包头 + 54B 链路/网络/传输头 + 载荷），与 tryExecPcapHTTP 的解析约定一致。
func buildTestPcap(payloadFlag string) []byte {
	var out []byte
	gh := make([]byte, 24)
	binary.LittleEndian.PutUint32(gh[0:4], 0xa1b2c3d4) // pcap magic
	binary.LittleEndian.PutUint16(gh[4:6], 2)          // version major
	binary.LittleEndian.PutUint16(gh[6:8], 4)          // version minor
	binary.LittleEndian.PutUint32(gh[16:20], 65535)    // snaplen
	out = append(out, gh...)

	pkt := make([]byte, 54) // eth(14)+ip(20)+tcp(20)
	pkt = append(pkt, []byte("POST /login HTTP/1.1\r\nContent-Length: 24\r\n\r\n"+payloadFlag)...)

	ph := make([]byte, 16)
	binary.LittleEndian.PutUint32(ph[8:12], uint32(len(pkt)))  // incl_len
	binary.LittleEndian.PutUint32(ph[12:16], uint32(len(pkt))) // orig_len
	out = append(out, ph...)
	out = append(out, pkt...)
	return out
}

// TestPresolveAttachmentRejectsPathOutsideRoot 安全门禁：
// 消息文本中若出现 chat_uploads 之外的路径（含 ../ 穿越），必须拒绝读取，
// 否则等于让任意用户消息把服务器任意文件灌进求解上下文。
func TestPresolveAttachmentRejectsPathOutsideRoot(t *testing.T) {
	outside := t.TempDir() // 位于系统临时目录，绝不在 chat_uploads 之下
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("flag{sh0uld_n0t_b3_r34d}"), 0o644); err != nil {
		t.Skipf("无法写入越界测试文件: %v", err)
	}

	desc := attachmentMarker + "\n- secret.txt: " + secret
	pr := NewPresolver(zap.NewNop())
	res := pr.Presolve(context.Background(), &Challenge{Description: desc}, nil)

	joined := strings.Join(res.Flags, " ")
	if strings.Contains(joined, "sh0uld_n0t_b3_r34d") {
		t.Fatalf("❌ 越界路径被读取，存在路径穿越风险: %v", res.Flags)
	}
	t.Logf("✅ 越界路径已拒绝读取（solved=%v）", res.Solved)
}
