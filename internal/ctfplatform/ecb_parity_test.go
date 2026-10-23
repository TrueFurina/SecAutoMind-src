package ctfplatform

// ECB 集的 Go 侧机验（对齐 data/ctf_benchmark/judge_ecb.py）。
//
// 该集 json 无 description，判定对象是**磁盘工件**（artifacts/ecb_penguin.png 与
// artifacts/cbc_penguin.png 成对），故走「pid → 内建判定」分派。
//
// 反注水三条（缺一条这个基准集就退化成"数重复块"）：
//   1. 正常成对（ECB 高 / CBC 低）必须命中；
//   2. **两张都换成 ECB 图**必须拒绝 —— 否则只看 ECB 侧阈值就能过；
//   3. **两张都换成 CBC 图**必须拒绝 —— 否则 ECB 阈值形同虚设。

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// ecbTargetFlag 与 gen_ecb_image.py 的 SCENE 逐字一致。
const ecbTargetFlag = "flag{aes_ecb_bl0ck_r3p34t_t3xtur3}"

// ecbArtifact 返回工件绝对（相对包目录的）路径。
func ecbArtifact(name string) string {
	return filepath.Join("..", "..", "data", "ctf_benchmark", "artifacts", name)
}

// requireECBArtifacts 工件缺失即 Skip（data/ 被 gitignore，干净检出里可能没有）。
func requireECBArtifacts(t *testing.T) (ecbPath, cbcPath string) {
	t.Helper()
	ecbPath, cbcPath = ecbArtifact("ecb_penguin.png"), ecbArtifact("cbc_penguin.png")
	for _, p := range []string{ecbPath, cbcPath} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("ECB 工件缺失（%s），跳过：先跑 python data/ctf_benchmark/gen_ecb_image.py", p)
		}
	}
	return ecbPath, cbcPath
}

// TestECBDetectPairRealArtifacts 正常成对必须命中，并打印两侧比值（便于对照 Python）。
func TestECBDetectPairRealArtifacts(t *testing.T) {
	ecbPath, cbcPath := requireECBArtifacts(t)
	ok, ecbRatio, cbcRatio, err := ecbDetectPair(ecbPath, cbcPath)
	if err != nil {
		t.Fatalf("检测失败: %v", err)
	}
	t.Logf("ECB dup=%.3f (>=%.2f) · CBC dup=%.3f (<=%.2f)", ecbRatio, ecbMinDup, cbcRatio, cbcMaxDup)
	if !ok {
		t.Fatalf("正常成对未命中：ECB=%.3f CBC=%.3f —— 阈值或取块口径被改坏了", ecbRatio, cbcRatio)
	}
	// 与 Python 侧实测值（0.934 / 0.000）交叉校验：口径漂了会在这里暴露
	if ecbRatio < 0.90 {
		t.Errorf("ECB 重复块率 %.3f 明显低于 Python 侧实测 0.934 —— 取字节口径不一致"+
			"（PIL convert('RGB').tobytes() 是 H*W*3 无行填充）", ecbRatio)
	}
	if cbcRatio > 0.01 {
		t.Errorf("CBC 重复块率 %.3f 明显高于 Python 侧实测 0.000 —— 对照图被污染或口径不符", cbcRatio)
	}
}

// TestECBDetectRejectsBothECB 两张都是 ECB 图必须拒绝（CBC_MAX 侧的反注水）。
func TestECBDetectRejectsBothECB(t *testing.T) {
	ecbPath, _ := requireECBArtifacts(t)
	ok, ecbRatio, cbcRatio, err := ecbDetectPair(ecbPath, ecbPath)
	if err != nil {
		t.Fatalf("检测失败: %v", err)
	}
	if ok {
		t.Fatalf("两张都是 ECB 图却判命中（ECB=%.3f CBC=%.3f）—— "+
			"CBC 对照阈值失效，纯色图/重复图会白拿分", ecbRatio, cbcRatio)
	}
}

// TestECBDetectRejectsBothCBC 两张都是 CBC 图必须拒绝（ECB_MIN 侧的反注水）。
func TestECBDetectRejectsBothCBC(t *testing.T) {
	_, cbcPath := requireECBArtifacts(t)
	ok, ecbRatio, cbcRatio, err := ecbDetectPair(cbcPath, cbcPath)
	if err != nil {
		t.Fatalf("检测失败: %v", err)
	}
	if ok {
		t.Fatalf("两张都是 CBC 图却判命中（ECB=%.3f CBC=%.3f）—— ECB 阈值形同虚设",
			ecbRatio, cbcRatio)
	}
}

// TestECBSuiteParityAgainstBenchmark 逐题机验：Go 侧判定必须与 Python 侧全中一致。
func TestECBSuiteParityAgainstBenchmark(t *testing.T) {
	bench := loadSuiteBench(t, "ecb_benchmark.json")
	if len(bench) == 0 {
		t.Fatal("[ecb] 基准集 problems 为空 —— 空洞绿，禁止判过")
	}

	runners := map[string]func(t *testing.T) (string, error){
		"ecb_penguin": func(t *testing.T) (string, error) {
			ecbPath, cbcPath := requireECBArtifacts(t)
			ok, ecbRatio, cbcRatio, err := ecbDetectPair(ecbPath, cbcPath)
			if err != nil {
				return "", err
			}
			if !ok {
				return "", fmt.Errorf("成对判定未命中（ECB=%.3f CBC=%.3f）", ecbRatio, cbcRatio)
			}
			return ecbTargetFlag, nil
		},
	}

	for pid := range bench {
		if _, ok := runners[pid]; !ok {
			t.Errorf("[ecb] json 含未实现分派的题 %q —— 覆盖度缺失（空洞绿风险）", pid)
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
			t.Logf("✅ HIT  %s", pid)
		} else {
			t.Logf("❌ MISS %s（flag sha256 不匹配）", pid)
		}
	}
	t.Logf("=== [ecb] Go 侧逐题: %d/%d ===", hits, len(bench))
	if hits < len(bench) {
		t.Errorf("[ecb] Go 逐题命中 %d/%d 低于全中门禁（Python judge 侧全中，双语言应当一致）",
			hits, len(bench))
	}
}
