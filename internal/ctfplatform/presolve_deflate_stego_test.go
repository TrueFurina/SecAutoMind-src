package ctfplatform

// presolve_deflate_stego_test.go —— deflate 隐码链 Go 化回归（合成口径）。
//
// 夹具 testdata/xhlj_deflate_stego.zip 由 python 测试 _synth_zip() 生成
// （test_misc_deflate_huffman_flag.py 的权威构造；flag = SCF{aik-survz}，
// python solve 自验通过）。原题载荷已丢失（GoogleCTF2021 lipogram，
// KNOWN_DATA_LOSS 家族）——合成口径不得冒充原始题解出。

import (
	"os"
	"testing"
)

func TestXHLJChain_DeflateStego(t *testing.T) {
	data, err := os.ReadFile("testdata/xhlj_deflate_stego.zip")
	if err != nil {
		t.Fatalf("夹具缺失（testdata/xhlj_deflate_stego.zip 应随仓入库）: %v", err)
	}
	if flag := solveDeflateStego(data); flag != "SCF{aik-survz}" {
		t.Fatalf("deflate 隐码链解出 %q，期望 SCF{aik-survz}", flag)
	}
}

func TestXHLJChain_DeflateStegoRegistryPath(t *testing.T) {
	data, err := os.ReadFile("testdata/xhlj_deflate_stego.zip")
	if err != nil {
		t.Fatalf("夹具缺失: %v", err)
	}
	flags := tryDeflateStego("misc stego", map[string]string{"lipogram.zip": string(data)})
	if len(flags) == 0 || flags[0] != "SCF{aik-survz}" {
		t.Fatalf("注册表路径未命中: %v", flags)
	}
}

// 负向：普通含 E 的 zip 文本流会被 lipogram 守卫拦下（不谎报）。
func TestXHLJChain_DeflateStegoNegative(t *testing.T) {
	if flag := solveDeflateStego([]byte("this is not a zip file at all, just text with E letters")); flag != "" {
		t.Fatalf("非 zip 输入不应命中: %q", flag)
	}
}
