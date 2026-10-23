package ctfplatform

// AES-ECB 块纹理识别（Go 侧镜像，对齐 data/ctf_benchmark/judge_ecb.py）。
//
// 真题对照：CTF 公开题 - AES ECB 企鹅（aes_ecb_penguin 能力面）。
// 判定原理：ECB 对相同明文块产生**相同密文块**，所以把图像原始 RGB 字节按 16 字节
// 切块后，重复块率极高；CBC 有链式反馈，相同明文块也产生不同密文块（雪崩），
// 重复块率极低。
//
// 反注水（与 Python 侧逐阈值一致）：必须**同时**满足
//     ECB 图重复块率 ≥ 0.30  且  CBC 图重复块率 ≤ 0.05
// 才计命中。只看 ECB 图会退化成"无脑数重复块"——任何纯色图都能骗过。

import (
	"fmt"
	"image"
	"image/png"
	"os"
)

const (
	// ecbMinDup ECB 图重复 16B 块率下限（与 judge_ecb.py 的 ECB_MIN 一致）。
	ecbMinDup = 0.30
	// cbcMaxDup CBC 对照图重复块率上限（与 judge_ecb.py 的 CBC_MAX 一致）。
	cbcMaxDup = 0.05
)

// ecbRGBBytes 把图像转成与 PIL `convert("RGB").tobytes()` 同序的 H*W*3 字节。
// 用 NRGBA 模型而不是直接右移 RGBA()：后者是**预乘 alpha**，半透明像素会失真。
func ecbRGBBytes(img image.Image) []byte {
	b := img.Bounds()
	out := make([]byte, 0, b.Dx()*b.Dy()*3)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, _ := img.At(x, y).RGBA()
			out = append(out, byte(r>>8), byte(g>>8), byte(bl>>8))
		}
	}
	return out
}

// ecbDupRatio 16 字节块重复率：1 - 唯一块数/总块数（与 Python 侧同口径）。
func ecbDupRatio(img image.Image) float64 {
	raw := ecbRGBBytes(img)
	if len(raw) < 16 {
		return 0
	}
	total := 0
	uniq := make(map[string]struct{}, len(raw)/16)
	for i := 0; i+16 <= len(raw); i += 16 {
		total++
		uniq[string(raw[i:i+16])] = struct{}{}
	}
	if total == 0 {
		return 0
	}
	return 1 - float64(len(uniq))/float64(total)
}

// ecbDupRatioFile 读 PNG 并算重复块率。
func ecbDupRatioFile(path string) (float64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		return 0, fmt.Errorf("解码 %s 失败: %w", path, err)
	}
	return ecbDupRatio(img), nil
}

// ecbDetectPair 成对判定：ECB 图重复率高 **且** CBC 图重复率低才算识别成功。
// 只给一个比值就下结论是无意义的——这正是该题的反注水点。
func ecbDetectPair(ecbPath, cbcPath string) (ok bool, ecbRatio, cbcRatio float64, err error) {
	ecbRatio, err = ecbDupRatioFile(ecbPath)
	if err != nil {
		return false, 0, 0, err
	}
	cbcRatio, err = ecbDupRatioFile(cbcPath)
	if err != nil {
		return false, ecbRatio, 0, err
	}
	return ecbRatio >= ecbMinDup && cbcRatio <= cbcMaxDup, ecbRatio, cbcRatio, nil
}
