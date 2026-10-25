package ctfplatform

// upx_adapter_test.go —— UPX 脱壳适配器回归。
//
// round-trip 用真 ELF（bench 附件 reverse_2）+ 真工具（upx 打包 → 适配器解包 →
// 字节级一致）；工具缺失时 SKIP（环境缺口不伪造绿）。helloupx11（反脱壳篡改样本）
// 只断言 looksUpxPacked 识别，不断言解包失败（当前行为的钉子，非目标行为）。

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func skipNoUpx(t *testing.T) {
	t.Helper()
	if _, err := upxPath(); err != nil {
		t.Skipf("upx 工具缺失（设 SECAUTOMIND_UPX 或安装 upx）: %v", err)
	}
}

func upxBenchPath(dir, name string) string {
	return filepath.Join("..", "..", "data", "questions_real_bench", "attachments", dir, name)
}

// upxPackForTest 用真实 upx 打包一段 ELF（临时文件往返；-o 输出）。
func upxPackForTest(orig []byte) ([]byte, error) {
	tool, err := upxPath()
	if err != nil {
		return nil, err
	}
	src, err := os.CreateTemp("", "secautomind-upx-pack-src-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(src.Name())
	if _, err := src.Write(orig); err != nil {
		src.Close()
		return nil, err
	}
	src.Close()
	dst := src.Name() + ".packed"
	defer os.Remove(dst)
	out, err := upxRunner(context.Background(), tool, "-o", dst, src.Name())
	if err != nil {
		return nil, fmt.Errorf("upx pack: %w（%s）", err, strings.TrimSpace(out))
	}
	return os.ReadFile(dst)
}

func TestUpxAdapterRoundTrip(t *testing.T) {
	skipNoUpx(t)
	orig, err := os.ReadFile(upxBenchPath("real_reverse_sheng", "reverse_2"))
	if err != nil {
		t.Skipf("bench 附件缺失: %v", err)
	}
	// upx 打包（输入本身是真 ELF；upx 只打包可执行格式）
	packed, err := upxPackForTest(orig)
	if err != nil {
		t.Skipf("upx 打包失败（工具/格式兼容）: %v", err)
	}
	if !looksUpxPacked(packed) {
		t.Fatalf("upx 打包产物未被 looksUpxPacked 识别（启发式失效）")
	}
	un, err := upxUnpack(context.Background(), packed)
	if err != nil {
		t.Fatalf("upxUnpack 失败: %v", err)
	}
	if string(un) != string(orig) {
		t.Fatalf("round-trip 字节不一致: orig=%d unpacked=%d", len(orig), len(un))
	}
}

func TestLooksUpxPackedHelloupx11(t *testing.T) {
	d, err := os.ReadFile(upxBenchPath("real_reverse_upx", "helloupx11"))
	if err != nil {
		t.Skipf("bench 附件缺失: %v", err)
	}
	if !looksUpxPacked(d) {
		t.Fatalf("helloupx11（UPX 形态 ELF + UPX! 魔数）未被识别")
	}
}
