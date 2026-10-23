package ctfplatform

// CRC64 集的 Go 侧机验（对齐 data/ctf_benchmark/judge_crc64.py 与 crc64_range.py）。
//
// 该集 json 无 description（交互型），故不用 runSuiteSweep，而用「pid → 内建靶机攻击」
// 分派（与 TestBlindOOBAgainstBenchmark 同构）：靶场用 httptest 在进程内起，
// 逐题跑真实攻击链，再拿 flag 的 sha256 与基准集比对。
//
// 除"能不能打通"外，本文件还钉住两条**反注水**性质（否则这个基准集就是自欺）：
//   1. 靶场只认「data 精确等于 admin 块」+ crc 校验通过 —— 换个块或换个 crc 都不给 flag；
//   2. 标准库 CRC64（ECMA/ISO）算出的 cookie **必须打不通** —— 证明自定义多项式
//      确实迫使攻击者走 oracle 学 Δ，而不是拿现成库函数糊过去。

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc64"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// crc64TargetFlag 靶场里的 flag（与 live_target/crc64_range.py 的 SCENES 逐字一致）。
const crc64TargetFlag = "flag{crc64_1s_n0t_4_m4c_b1tfl1p}"

// newCRC64Target 起一个 Go 原生 CRC64 靶场（复刻 Python 侧四条路由与校验语义）。
func newCRC64Target(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, code int, body map[string]interface{}) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(body)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			writeJSON(w, 404, map[string]interface{}{"ok": false, "msg": "not found"})
			return
		}
		_, _ = w.Write([]byte("<h1>CRC64 Range</h1>"))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]interface{}{
			"ok":   true,
			"data": hex.EncodeToString(crc64GuestBlock),
			"crc":  fmt.Sprintf("%016x", crc64Custom(crc64GuestBlock)),
		})
	})
	mux.HandleFunc("/oracle", func(w http.ResponseWriter, r *http.Request) {
		raw, err := hex.DecodeString(r.URL.Query().Get("data"))
		if err != nil || len(raw) == 0 {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "msg": "bad hex"})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"ok":  true,
			"crc": fmt.Sprintf("%016x", crc64Custom(raw)),
		})
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		cookie := r.URL.Query().Get("cookie")
		parts := strings.SplitN(cookie, ".", 2)
		if len(parts) != 2 {
			writeJSON(w, 403, map[string]interface{}{"ok": false, "msg": "bad cookie format"})
			return
		}
		data, err := hex.DecodeString(parts[0])
		if err != nil {
			writeJSON(w, 403, map[string]interface{}{"ok": false, "msg": "bad data"})
			return
		}
		given, err := strconv.ParseUint(parts[1], 16, 64)
		if err != nil {
			writeJSON(w, 403, map[string]interface{}{"ok": false, "msg": "bad crc"})
			return
		}
		if string(data) != string(crc64AdminBlock) {
			writeJSON(w, 403, map[string]interface{}{"ok": false, "msg": "not admin"})
			return
		}
		if given != crc64Custom(data) {
			writeJSON(w, 403, map[string]interface{}{"ok": false, "msg": "integrity check failed"})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"ok": true, "flag": crc64TargetFlag})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestCRC64Linearity CRC 在 INIT/XOROUT=0 时是严格线性映射 —— 这是整个攻击的数学前提。
// 若有人"优化"靶场参数（比如给 INIT 加个非零初值），这条会立刻红。
func TestCRC64Linearity(t *testing.T) {
	a := []byte("0123456789abcdef")
	b := []byte("fedcba9876543210")
	if len(a) != len(b) {
		t.Fatal("前置：两块必须等长")
	}
	x := make([]byte, len(a))
	for i := range a {
		x[i] = a[i] ^ b[i]
	}
	if got, want := crc64Custom(x), crc64Custom(a)^crc64Custom(b); got != want {
		t.Fatalf("线性性不成立：crc(a⊕b)=%016x，crc(a)⊕crc(b)=%016x —— "+
			"INIT/XOROUT 被改成非零了吗？", got, want)
	}
}

// TestCRC64StandardLibraryCannotForge 反注水：标准库 CRC64（ECMA/ISO）算的 cookie 必须打不通。
// 证明「自定义多项式」不是装饰——攻击者必须真的走 oracle 学 Δ。
func TestCRC64StandardLibraryCannotForge(t *testing.T) {
	srv := newCRC64Target(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		tab  *crc64.Table
	}{
		{"ECMA", crc64.MakeTable(crc64.ECMA)},
		{"ISO", crc64.MakeTable(crc64.ISO)},
	} {
		sum := crc64.Checksum(crc64AdminBlock, tc.tab)
		cookie := hex.EncodeToString(crc64AdminBlock) + "." + fmt.Sprintf("%016x", sum)
		resp := crc64JSONGet(ctx, srv.URL+"/admin?cookie="+cookie)
		if resp == nil {
			t.Fatalf("[%s] /admin 不可达", tc.name)
		}
		if ok, _ := resp["ok"].(bool); ok {
			t.Fatalf("[%s] 标准库 CRC64 竟然通过了完整性校验 —— 靶场退化成"+
				"「拿现成库函数就能过」，基准集失去意义", tc.name)
		}
	}
}

// TestCRC64WrongBlockRejected 反注水：块不是 admin 时必须拒绝（哪怕 crc 自洽）。
func TestCRC64WrongBlockRejected(t *testing.T) {
	srv := newCRC64Target(t)
	other := []byte("user=root\x00\x00\x00\x00\x00\x00")
	cookie := hex.EncodeToString(other) + "." + fmt.Sprintf("%016x", crc64Custom(other))
	resp := crc64JSONGet(context.Background(), srv.URL+"/admin?cookie="+cookie)
	if resp == nil {
		t.Fatal("/admin 不可达")
	}
	if ok, _ := resp["ok"].(bool); ok {
		t.Fatal("非 admin 块却通过了校验 —— flag 会白送，基准集无意义")
	}
}

// TestCRC64SuiteParityAgainstBenchmark 逐题机验：Go 侧攻击链必须全中。
func TestCRC64SuiteParityAgainstBenchmark(t *testing.T) {
	bench := loadSuiteBench(t, "crc64_benchmark.json")
	if len(bench) == 0 {
		t.Fatal("[crc64] 基准集 problems 为空 —— 空洞绿，禁止判过")
	}

	runners := map[string]func(t *testing.T) (string, error){
		"crc64_bitflip": func(t *testing.T) (string, error) {
			srv := newCRC64Target(t)
			return crc64BitflipAttack(context.Background(), srv.URL)
		},
	}

	// 覆盖度自证：json 每个 pid 都必须有分派，否则新增题会静默漏跑。
	for pid := range bench {
		if _, ok := runners[pid]; !ok {
			t.Errorf("[crc64] json 含未实现分派的题 %q —— 覆盖度缺失（空洞绿风险）", pid)
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
			t.Logf("❌ MISS %s（攻击未打通：%v）", pid, err)
			continue
		}
		if flagMatchesSHA([]string{flag}, bench[pid].FlagSHA256) {
			hits++
			t.Logf("✅ HIT  %s", pid)
		} else {
			t.Logf("❌ MISS %s（拿到 flag 但 sha256 不匹配：%q）", pid, flag)
		}
	}
	t.Logf("=== [crc64] Go 侧逐题: %d/%d ===", hits, len(bench))
	if hits < len(bench) {
		t.Errorf("[crc64] Go 逐题命中 %d/%d 低于全中门禁（Python judge 侧全中，双语言应当一致）",
			hits, len(bench))
	}
}
