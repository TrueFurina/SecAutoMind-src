package ctfplatform

// 跨集逐题 parity（Go 侧）——把对外汇总里【16】～【22】那句「Python judge == Go solver」
// 从**措辞**变成**逐题机验**。
//
// ## 背景（AGENTS.md 第八条：宣称 ≠ 接线）
//
// data/ctf_benchmark/run_all_benchmarks.py 的汇总里，各集都打印一句「Python xxx == Go xxx」。
// 但长期以来 Go 侧只跑**合成单元测试**（TestXxxSolverParses 之类），从不读基准 json 做逐题 sweep；
// 即「双语言互相印证」这句宣称里，Go 那一半从未对着同一批题跑过。
// scripts/check_suite_parity.py 台账门禁已把范围从手写改成机验，但【16】～【22】仍标 unwired。
//
// ## 本文件做什么
//
// 对这 7 集（blind_oob / hash_ext / gcm_nonce_reuse / mt19937 / lfsr / lcg / crc32）：
//   - 读各自 benchmark.json 的 problems；
//   - 逐题把 description 喂给**生产注册表里的求解器**（即 Go 生产路径，不是测试专用后门）；
//   - 把产出的候选 flag 逐个 sha256，与 json 里的 flag_sha256 比对；
//   - 打印与 ecdsa/padding_oracle 同构的 `✅ HIT  <pid>` / `❌ MISS <pid>`，
//     供 scripts/check_suite_parity.py 解析后与 Python judge 逐题集合比对。
//
// **每集一个独立顶层测试函数**——这是与既有接线（TestECDSANonceReuseAgainstBenchmark 等）
// 的约定：门禁按 `-run <顶层测试名>` 取数，若多集共用一个测试，输出会混入他集 pid
// 导致「逐题集合一致」判据误判。
//
// ## 为什么这 7 集此前判「Go 侧无逐题可比」是错的
//
// 侦察结论：7 集 Go 侧**都有对应的生产求解器**（web_blind_oob / hash_length_extension /
// gcm_nonce_reuse / mt19937_recover / lfsr_predict / lcg_predict / crc32_forge），
// 6 个 crypto 集的 json description 完全自包含（含 nonce/ct/hash/bits/params 等真实输入），
// 可直接喂 solver；blind_oob 的 json 虽无 description，但两侧硬编码秘密的 sha256
// 与 json 的 flag_sha256 **精确相等**，故同样可逐题机验。
//
// ## 防空洞绿
//
// 每个集都带**覆盖度断言**：problems 为空 → 直接 Fatal（0 题 ⇒ 命中恒为 0/0 ⇒ 若只判
// `hits < total` 就是恒绿的第三种空洞绿形态）。blind_oob 另带「json 的 pid ⊆ 已实现分派」
// 断言，防止 json 加题后静默漏跑。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// suiteProblem 是各集 benchmark.json 里单题的公共形状。
type suiteProblem struct {
	Description string `json:"description"`
	FlagSHA256  string `json:"flag_sha256"`
}

// loadSuiteBench 读 data/ctf_benchmark/<name> 的 problems；文件缺失时 skip（CI 上均入库）。
func loadSuiteBench(t *testing.T, name string) map[string]suiteProblem {
	t.Helper()
	path := filepath.Join("..", "..", "data", "ctf_benchmark", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("%s 缺失，跳过（CI 上该文件已入库，不应发生）", name)
	}
	var bench struct {
		Problems map[string]suiteProblem `json:"problems"`
	}
	if err := json.Unmarshal(raw, &bench); err != nil {
		t.Fatalf("解析 %s 失败: %v", name, err)
	}
	return bench.Problems
}

// flagMatchesSHA 判定候选集中是否有任一 flag 的 sha256 == want（大小写归一）。
func flagMatchesSHA(flags []string, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	if want == "" {
		return false
	}
	for _, f := range flags {
		sum := sha256.Sum256([]byte(f))
		if hex.EncodeToString(sum[:]) == want {
			return true
		}
	}
	return false
}

// runSuiteSweep 逐题跑 solver 并与 json 的 flag_sha256 比对，打印门禁可解析的命中行。
// pid 排序保证输出稳定（map 遍历顺序随机会让日志/diff 抖动）。
func runSuiteSweep(t *testing.T, suite, jsonFile string, solver ContextSolverFunc) {
	t.Helper()
	bench := loadSuiteBench(t, jsonFile)
	if len(bench) == 0 {
		t.Fatalf("[%s] 基准集 problems 为空 —— 0 题会让命中判据恒真（空洞绿），禁止判过", suite)
	}
	pids := make([]string, 0, len(bench))
	for pid := range bench {
		pids = append(pids, pid)
	}
	sort.Strings(pids)

	hits := 0
	for _, pid := range pids {
		flags := solver(context.Background(), bench[pid].Description, nil)
		if flagMatchesSHA(flags, bench[pid].FlagSHA256) {
			hits++
			t.Logf("✅ HIT  %s", pid)
		} else {
			t.Logf("❌ MISS %s", pid)
		}
	}
	t.Logf("=== [%s] Go 侧逐题: %d/%d ===", suite, hits, len(bench))
	if hits < len(bench) {
		t.Errorf("[%s] Go 逐题命中 %d/%d 低于全中门禁（Python judge 侧全中，双语言应当一致）",
			suite, hits, len(bench))
	}
}

// ── 6 个 crypto 集：json description 自包含，solver 直接吃文本 ──────────────

func TestHashExtSuiteParityAgainstBenchmark(t *testing.T) {
	runSuiteSweep(t, "hash_ext", "hash_ext_benchmark.json", solveHashLengthExtension)
}

func TestGCMNonceReuseSuiteParityAgainstBenchmark(t *testing.T) {
	runSuiteSweep(t, "gcm_nonce_reuse", "gcm_nonce_reuse_benchmark.json", solveGCMNonceReuse)
}

func TestMT19937SuiteParityAgainstBenchmark(t *testing.T) {
	runSuiteSweep(t, "mt19937", "mt19937_benchmark.json", solveMT19937)
}

func TestLFSRSuiteParityAgainstBenchmark(t *testing.T) {
	runSuiteSweep(t, "lfsr", "lfsr_benchmark.json", solveLFSRPredict)
}

func TestLCGSuiteParityAgainstBenchmark(t *testing.T) {
	runSuiteSweep(t, "lcg", "lcg_benchmark.json", solveLCGPredict)
}

func TestCRC32SuiteParityAgainstBenchmark(t *testing.T) {
	runSuiteSweep(t, "crc32", "crc32_benchmark.json", solveCRC32Forge)
}

// TestBlindOOBAgainstBenchmark 对 blind_oob 集逐题机验。
//
// 该集 json 无 description（需实时靶机交互），但两侧硬编码秘密的 sha256 与 json 的
// flag_sha256 精确相等 —— 故用「pid → 内建靶机攻击」分派做逐题机验，并断言
// json 的 pid 集合 ⊆ 已实现分派（防 json 加题后静默漏跑）。
func TestBlindOOBAgainstBenchmark(t *testing.T) {
	bench := loadSuiteBench(t, "blind_oob_benchmark.json")
	if len(bench) == 0 {
		t.Fatal("[blind_oob] 基准集 problems 为空 —— 空洞绿，禁止判过")
	}

	// pid → 内建靶机攻击，返回还原出的秘密。
	runners := map[string]func() string{
		"time_blind_basic": func() string {
			target := newTimeTarget(blindTimeSecret)
			defer target.Close()
			oracle := func(ctx context.Context, cond string) (time.Duration, error) {
				q, err := url.ParseQuery(cond)
				if err != nil {
					return 0, err
				}
				u := target.URL + "/time?pos=" + q.Get("pos") + "&c=" + q.Get("c")
				t0 := time.Now()
				resp, err := http.Get(u)
				if err != nil {
					return 0, err
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				return time.Since(t0), nil
			}
			return TimeBlindRecover(context.Background(), oracle, len(blindTimeSecret), blindCharset, 120*time.Millisecond)
		},
		"oob_exfil_basic": func() string {
			target := newOOBTarget(blindOOBSecret)
			defer target.Close()
			oob := StartOOBListener()
			defer oob.Close()
			trigger := func(oobBase string) error {
				u := target.URL + "/oob?cb=" + url.QueryEscape(oobBase+"/?d=")
				resp, err := http.Get(u)
				if err != nil {
					return err
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				return nil
			}
			got, _ := OOBExtract(oob, trigger, func(raw string) string {
				if f := scanFlags(raw); len(f) > 0 {
					return f[0]
				}
				return ""
			})
			return got
		},
	}

	// 覆盖度自证：json 里的每个 pid 都必须有已实现的分派，否则新增题会静默漏跑。
	for pid := range bench {
		if _, ok := runners[pid]; !ok {
			t.Errorf("[blind_oob] json 含未实现分派的题 %q —— 覆盖度缺失（空洞绿风险），"+
				"须在本测试补对应 runner", pid)
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
			continue // 已在上面报覆盖度错误
		}
		if flagMatchesSHA([]string{run()}, bench[pid].FlagSHA256) {
			hits++
			t.Logf("✅ HIT  %s", pid)
		} else {
			t.Logf("❌ MISS %s", pid)
		}
	}
	t.Logf("=== [blind_oob] Go 侧逐题: %d/%d ===", hits, len(bench))
	if hits < len(bench) {
		t.Errorf("[blind_oob] Go 逐题命中 %d/%d 低于全中门禁", hits, len(bench))
	}
}
