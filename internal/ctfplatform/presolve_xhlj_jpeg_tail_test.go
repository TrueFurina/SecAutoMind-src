package ctfplatform

// presolve_xhlj_jpeg_tail_test.go —— xuanhun_signin 链 Go 化回归（合成口径）。
//
// 原始载荷（xz1.jpg）已永久丢失（2026-10-12 数据丢失事件，KNOWN_DATA_LOSS），
// 合成实例构造与 chain_verify_20261024.json 的 xuanhun 条目同批同构：
// 合成 JPEG(SOI+filler+FFD9) 尾嵌 PNG(tEXt flag)，flag = flag{SYNTH_XUANHUN_JPEG_TAIL_PNG}。
// 本测试钉住 Go 侧 bin_jpeg_tail 求解器（JPEG 体内嵌 PNG 偏移定位 + tEXt 块级解析），
// 不得冒充原始题解出（吞并路线图 §五.2 REGRESS_PASS 合成口径）。

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// pngChunk 组一个 PNG 块（长度+类型+数据+CRC 占位——回归只测解析器，不验 CRC）。
func pngChunk(typ string, data []byte) []byte {
	out := make([]byte, 12+len(data))
	binary.BigEndian.PutUint32(out[:4], uint32(len(data)))
	copy(out[4:8], typ)
	copy(out[8:8+len(data)], data)
	return out
}

func synthJpegTailPng() []byte {
	var d []byte
	d = append(d, 0xFF, 0xD8, 0xFF, 0xE0) // JPEG SOI + APP0 头
	app0 := make([]byte, 16)
	app0[0], app0[1] = 0x00, 0x10
	d = append(d, app0...)
	d = append(d, 0xFF, 0xDA, 0x00, 0x02) // SOS（无扫描数据的最小形）
	d = append(d, 0xFF, 0xD9)             // EOI
	// 尾嵌 PNG：签名 + IHDR + tEXt(flag\0value) + IEND
	d = append(d, 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n')
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[:4], 1)
	binary.BigEndian.PutUint32(ihdr[4:8], 1)
	ihdr[8], ihdr[9], ihdr[10], ihdr[11], ihdr[12] = 8, 2, 0, 0, 0
	d = append(d, pngChunk("IHDR", ihdr)...)
	d = append(d, pngChunk("tEXt", []byte("flag\x00flag{SYNTH_XUANHUN_JPEG_TAIL_PNG}"))...)
	d = append(d, pngChunk("IEND", nil)...)
	return d
}

func TestXHLJChain_XuanhunJpegTailPng(t *testing.T) {
	d := synthJpegTailPng()
	got := strings.Join(bfxJpegTailPng(d), "\n")
	if !strings.Contains(strings.ToLower(got), "flag{synth_xuanhun_jpeg_tail_png}") {
		t.Fatalf("xuanhun 链（JPEG 尾嵌 PNG→tEXt）未在 Go 侧命中：\n%s", got)
	}
}

// TestXHLJChain_XuanhunRegistryPath 走注册表全路径（bin_jpeg_tail 经 bfxRun 收
// 二进制附件），锁「附件字节 → 求解器」的二进制通道。
func TestXHLJChain_XuanhunRegistryPath(t *testing.T) {
	pr := NewPresolver(zap.NewNop())
	res := pr.PresolveWithRegistry(context.Background(), &Challenge{
		ID: "real_misc_xuanhun_signin", Category: "misc",
		Description: "签到题，附件是一张图。flag 格式 flag{...}",
	}, map[string]string{"xz1.jpg": string(synthJpegTailPng())})
	if res == nil || !res.Solved || len(res.Flags) == 0 {
		t.Fatalf("注册表路径未命中（bin_jpeg_tail 未被调度或解析失败）")
	}
	// bfxScanVariants 会产出去下划线等变体——任一候选命中即算（真值由 sha256 口径把守）。
	ok := false
	for _, f := range res.Flags {
		if strings.Contains(strings.ToLower(f), "flag{synth_xuanhun") {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("注册表路径候选非预期: %v", res.Flags)
	}
}
