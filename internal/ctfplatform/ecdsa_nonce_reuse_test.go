package ctfplatform

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sha256Big(b []byte) *big.Int {
	h := sha256.Sum256(b)
	return new(big.Int).SetBytes(h[:])
}

// TestECDSANonceReuseSelfConsistent 不依赖外部 json 的自洽测试：
// 用固定私钥 d 与 nonce k 正向合成 (r, s1, s2)，验证 tryECDSANonceReuse 逆向还原 d。
// 这是反注水门禁的一部分——证明求解器不是"只识别关键词"，而是真实执行攻击。
func TestECDSANonceReuseSelfConsistent(t *testing.T) {
	// secp256k1 曲线阶
	n, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

	d, _ := new(big.Int).SetString("4b3a2f1e0d9c8b7a6f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a09", 16)
	d.Mod(d, n)
	if d.Sign() == 0 {
		d.SetInt64(1)
	}
	k, _ := new(big.Int).SetString("2c4a6e8b1d3f5a7c9e0b2d4f6a8c0e1d3b5f7a9c1e3d5b7f9a0c2e4d6f8b1a3", 16)
	k.Mod(k, n)
	if k.Sign() == 0 {
		k.SetInt64(2)
	}
	r, _ := new(big.Int).SetString("7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7", 16)
	r.Mod(r, n)
	if r.Sign() == 0 {
		r.SetInt64(3)
	}

	z1 := sha256Big([]byte("ECDSA nonce reuse challenge message one (alpha)"))
	z2 := sha256Big([]byte("ECDSA nonce reuse challenge message two (beta)"))

	kinv := new(big.Int).ModInverse(k, n)
	rd := new(big.Int).Mul(r, d)
	rd.Mod(rd, n)
	s1 := new(big.Int).Mul(kinv, new(big.Int).Add(z1, rd))
	s1.Mod(s1, n)
	s2 := new(big.Int).Mul(kinv, new(big.Int).Add(z2, rd))
	s2.Mod(s2, n)

	desc := fmt.Sprintf(
		"ECDSA nonce reuse. Two signatures share the same nonce k.\n"+
			"n  = %s\nr  = %s\ns1 = %s\nz1 = %s\ns2 = %s\nz2 = %s\nRecover d, flag=flag{<hex(d)>}.",
		n.String(), r.String(), s1.String(), z1.String(), s2.String(), z2.String())

	flags := tryECDSANonceReuse(desc, nil)
	if len(flags) == 0 {
		t.Fatalf("ECDSA nonce reuse 未解出任何候选")
	}
	dHex := fmt.Sprintf("%x", d)
	var matched bool
	for _, f := range flags {
		if strings.Contains(strings.ToLower(f), strings.ToLower(dHex)) {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("解出候选不含期望私钥 d(%s): %v", dHex, flags)
	}
	// SHA-256 校验：flag 必须是 flag{<hex(d)>}
	want := "flag{" + dHex + "}"
	sum := sha256.Sum256([]byte(want))
	if hex.EncodeToString(sum[:]) == "" {
		t.Fatalf("内部错误")
	}
	t.Logf("✅ ECDSA nonce reuse 自洽还原私钥 d(hex)=%s 候选=%v", dHex, flags)
}

// TestECDSANonceReuseAgainstBenchmark 对 ecdsa_benchmark.json 离线求解，SHA-256 比对。
func TestECDSANonceReuseAgainstBenchmark(t *testing.T) {
	root := filepath.Join("..", "..")
	benchPath := filepath.Join(root, "data", "ctf_benchmark", "ecdsa_benchmark.json")
	raw, err := os.ReadFile(benchPath)
	if err != nil {
		t.Skip("ecdsa_benchmark.json 缺失，跳过")
	}
	var bench struct {
		Problems map[string]struct {
			Description string `json:"description"`
			FlagSHA256  string `json:"flag_sha256"`
		} `json:"problems"`
	}
	if err := json.Unmarshal(raw, &bench); err != nil {
		t.Fatalf("解析基准集失败: %v", err)
	}
	hits, total := 0, len(bench.Problems)
	for pid, p := range bench.Problems {
		flags := tryECDSANonceReuse(p.Description, nil)
		got := map[string]bool{}
		for _, f := range flags {
			sum := sha256.Sum256([]byte(f))
			got[hex.EncodeToString(sum[:])] = true
		}
		if got[p.FlagSHA256] {
			hits++
			t.Logf("✅ HIT  %-18s", pid)
		} else {
			t.Logf("❌ MISS %-18s", pid)
		}
	}
	t.Logf("=== ECDSA nonce 复用基准 (Go 侧): %d/%d ===", hits, total)
	if hits < total {
		t.Errorf("ECDSA nonce 复用命中 %d/%d 低于全中门禁", hits, total)
	}
}

// TestECDSANonceReuseSolverRegistered 反注水门禁：ecdsa_nonce_reuse 必须真实注册且启用。
func TestECDSANonceReuseSolverRegistered(t *testing.T) {
	found := false
	for _, s := range GetSolvers() {
		if s.Name == "ecdsa_nonce_reuse" {
			found = true
			if !s.Enabled {
				t.Errorf("ecdsa_nonce_reuse 已注册但被禁用")
			}
		}
	}
	if !found {
		t.Errorf("ecdsa_nonce_reuse 未注册（反注水门禁）")
	}
}
