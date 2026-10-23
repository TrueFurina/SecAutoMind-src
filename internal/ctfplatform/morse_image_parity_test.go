package ctfplatform

// Morse 时序图集的 Go 侧机验（对齐 data/ctf_benchmark/judge_morse_image.py）。
//
// 判定对象是磁盘工件 artifacts/morse_timing.png，故走「pid → 内建判定」分派。
//
// 反注水四条：
//   1. 解码文本必须**逐字**等于 Python 侧结果（口径漂了立刻红）；
//   2. **纯白图**（无任何符号）必须解出空串 —— 否则"有图就给 flag"；
//   3. **错误 dot/dash 阈值**必须解出不同的东西 —— 证明分类阈值真的在起作用；
//   4. **错误间隔阈值**同理 —— 证明符号/字符间隔语义不是装饰。

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// morseExpectedText Python 侧实测解码结果（judge_morse_image.py 输出 flag{m0rs31m4g3t1m1ngch4rt}）。
// 注意 Go 侧复用的 morseTable 值本身是小写，故这里取小写形态。
const morseExpectedText = "m0rs31m4g3t1m1ngch4rt"

func morseArtifact() string {
	return filepath.Join("..", "..", "data", "ctf_benchmark", "artifacts", "morse_timing.png")
}

func requireMorseArtifact(t *testing.T) string {
	t.Helper()
	p := morseArtifact()
	if _, err := os.Stat(p); err != nil {
		t.Skipf("Morse 工件缺失（%s），跳过：先跑 python data/ctf_benchmark/gen_morse_image.py", p)
	}
	return p
}

func loadPNG(t *testing.T, path string) image.Image {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("打开 %s 失败: %v", path, err)
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		t.Fatalf("解码 %s 失败: %v", path, err)
	}
	return img
}

// TestMorseDecodeExactText 解码文本逐字比对（最强的一条口径钉）。
func TestMorseDecodeExactText(t *testing.T) {
	img := loadPNG(t, requireMorseArtifact(t))
	got := morseDecodeImage(img, morseRunT, morseGapT)
	if got != morseExpectedText {
		t.Fatalf("解码结果不符\n got=%q\nwant=%q\n（取行位置 / 亮度阈值 / dot-dash 阈值 / 间隔阈值 任一漂移都会到这里）",
			got, morseExpectedText)
	}
}

// TestMorseDecodeBlankImageDoesNotHit 纯色图不得命中基准集。
//
// 注意（实测，别写成"空串"）：纯白图整行都是 on-run，会解出一个单符号 "t"
// （`-` → t）——Python 侧同口径同结果。所以反注水判据不是"解出空串"，而是
// **解出的 flag 绝不能等于基准 flag**：空图给不了分。
func TestMorseDecodeBlankImageDoesNotHit(t *testing.T) {
	bench := loadSuiteBench(t, "morse_image_benchmark.json")
	if len(bench) == 0 {
		t.Fatal("[morse_image] 基准集 problems 为空 —— 空洞判过")
	}
	for _, tc := range []struct {
		name string
		fill color.Color
	}{
		{"纯白", color.White},
		{"纯黑", color.Black},
	} {
		img := image.NewRGBA(image.Rect(0, 0, 200, 20))
		for y := 0; y < 20; y++ {
			for x := 0; x < 200; x++ {
				img.Set(x, y, tc.fill)
			}
		}
		text := morseDecodeImage(img, morseRunT, morseGapT)
		flag := "flag{" + strings.ToLower(text) + "}"
		for pid, p := range bench {
			if flagMatchesSHA([]string{flag}, p.FlagSHA256) {
				t.Fatalf("[%s] 纯色图解出 %q 竟命中 %s —— 基准集可被空图攻破（注水）",
					tc.name, flag, pid)
			}
		}
		t.Logf("[%s] 解出 %q → 未命中（符合预期）", tc.name, flag)
	}
}

// TestMorseDecodeWrongRunThresholdDiffers 变异：dot/dash 阈值改坏必须解出不同结果。
func TestMorseDecodeWrongRunThresholdDiffers(t *testing.T) {
	img := loadPNG(t, requireMorseArtifact(t))
	base := morseDecodeImage(img, morseRunT, morseGapT)
	for _, wrong := range []int{1, 12} {
		if got := morseDecodeImage(img, wrong, morseGapT); got == base {
			t.Errorf("把 dot/dash 阈值从 %d 改成 %d 后解码结果不变（%q）—— "+
				"该阈值形同虚设，分类逻辑没真正生效", morseRunT, wrong, base)
		}
	}
}

// TestMorseDecodeWrongGapThresholdDiffers 变异：符号/字符间隔阈值改坏必须解出不同结果。
func TestMorseDecodeWrongGapThresholdDiffers(t *testing.T) {
	img := loadPNG(t, requireMorseArtifact(t))
	base := morseDecodeImage(img, morseRunT, morseGapT)
	for _, wrong := range []int{0, 40} {
		if got := morseDecodeImage(img, morseRunT, wrong); got == base {
			t.Errorf("把间隔阈值从 %d 改成 %d 后解码结果不变（%q）—— "+
				"字符切分语义没真正生效", morseGapT, wrong, base)
		}
	}
}

// TestMorseImageSuiteParityAgainstBenchmark 逐题机验。
func TestMorseImageSuiteParityAgainstBenchmark(t *testing.T) {
	bench := loadSuiteBench(t, "morse_image_benchmark.json")
	if len(bench) == 0 {
		t.Fatal("[morse_image] 基准集 problems 为空 —— 空洞绿，禁止判过")
	}

	runners := map[string]func(t *testing.T) (string, error){
		"morse_image": func(t *testing.T) (string, error) {
			p := requireMorseArtifact(t)
			flag, err := morseDecodeFlagFile(p)
			if err != nil {
				return "", err
			}
			if !strings.HasPrefix(flag, "flag{") || len(flag) <= len("flag{}") {
				return "", fmt.Errorf("解码为空或形态不对: %q", flag)
			}
			return flag, nil
		},
	}

	for pid := range bench {
		if _, ok := runners[pid]; !ok {
			t.Errorf("[morse_image] json 含未实现分派的题 %q —— 覆盖度缺失（空洞绿风险）", pid)
		}
	}

	pids := make([]string, 0, len(bench))
	for pid := range bench {
		pids = append(pids, pid)
	}
	sort.Strings(pids)

	hits := 0
	for _, pid := range pids {
		run, ok := runners[pid]
		if !ok {
			continue
		}
		flag, err := run(t)
		if err != nil {
			t.Logf("❌ MISS %s（%v）", pid, err)
			continue
		}
		if flagMatchesSHA([]string{flag}, bench[pid].FlagSHA256) {
			hits++
			// 注意：pid 后面必须留空格，否则门禁的 `✅\s+HIT\s+(\S+)` 会把
			// "（decoded=...）" 一起吞进 key，与 Python 侧 key 对不上 → 假红。
			t.Logf("✅ HIT  %s (decoded=%s)", pid, flag)
		} else {
			t.Logf("❌ MISS %s（解码得 %q，sha256 不匹配）", pid, flag)
		}
	}
	t.Logf("=== [morse_image] Go 侧逐题: %d/%d ===", hits, len(bench))
	if hits < len(bench) {
		t.Errorf("[morse_image] Go 逐题命中 %d/%d 低于全中门禁（Python judge 侧全中）",
			hits, len(bench))
	}
}
