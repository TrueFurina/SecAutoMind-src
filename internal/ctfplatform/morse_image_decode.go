package ctfplatform

// Morse 时序图解码（Go 侧镜像，对齐 data/ctf_benchmark/judge_morse_image.py）。
//
// 真题对照：SpookyCTF 2024 - whispers-in-morse（public_morse_image 能力面）。
// 判定路径：PNG 像素 → **中间行** run-length → dot/dash 与符号/字符间隔分类 →
//           Morse 解码 → flag{解码内容小写} → SHA-256 比对。
//
// 反注水：图中没有任何可读文字；必须同时满足「run 宽度语义」与「间隔语义」，
// 任何一步错乱（阈值、取行位置、阈值方向）都会解出别的东西 → MISS。
// 因此本文件把两个阈值做成参数，测试里用**错误阈值**做变异，证明它们真的在起作用。

import (
	"fmt"
	"image"
	"image/png"
	"os"
	"strings"
)

const (
	// morseRunT dot/dash 阈值：宽度 <= 4 判 dot，> 4 判 dash。
	morseRunT = 4
	// morseGapT 符号/字符间隔阈值：<= 5 视为同一字符内的符号间隔，> 5 收尾当前字符。
	morseGapT = 5
)

// 复用 presolve_classical.go 的 morseTable（Morse → 小写字符，含 0-9）。
// 不另立一份：两处表一旦分叉，图片解码与文本解码会给出不同结果（同类"双表漂移"坑）。
// 注意它的方向是「码 → 字符」，正好是解码所需；Python 侧是「字符 → 码」再反转，
// 最终文本一致（都归到小写）。

// morseDecodeImage 取中间行做 run-length，再按阈值分类解码。
// runT/gapT 参数化：生产调用传 morseRunT/morseGapT，测试用别的值做变异。
func morseDecodeImage(img image.Image, runT, gapT int) string {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w == 0 || h == 0 {
		return ""
	}
	y := b.Min.Y + h/2

	// 亮度阈值 127（与 Python 侧 `img.getpixel(...)[0] > 127` 同口径，取 R 通道）
	on := make([]bool, w)
	for x := 0; x < w; x++ {
		r, _, _, _ := img.At(b.Min.X+x, y).RGBA()
		on[x] = r>>8 > 127
	}

	// run-length
	type run struct {
		on bool
		n  int
	}
	runs := make([]run, 0, 32)
	for i := 0; i < w; {
		j := i
		for j < w && on[j] == on[i] {
			j++
		}
		runs = append(runs, run{on: on[i], n: j - i})
		i = j
	}

	// 组装 token：on-run 是符号；off-run 超过 gapT 则收尾当前字符
	var tokens []string
	var cur strings.Builder
	for _, r := range runs {
		if r.on {
			if r.n > runT {
				cur.WriteByte('-')
			} else {
				cur.WriteByte('.')
			}
			continue
		}
		if cur.Len() > 0 && r.n > gapT {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}

	var text strings.Builder
	for _, t := range tokens {
		if ch, ok := morseTable[t]; ok {
			text.WriteString(ch) // morseTable 的值已是小写字符
		}
	}
	return text.String()
}

// morseDecodeFlagFile 读 PNG → 解码 → 拼 flag{小写}。
func morseDecodeFlagFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		return "", fmt.Errorf("解码 %s 失败: %w", path, err)
	}
	text := morseDecodeImage(img, morseRunT, morseGapT)
	return "flag{" + strings.ToLower(text) + "}", nil
}
