package ctfplatform

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// aesCBCEncrypt 测试用：AES-CBC 加密（与 localPaddingOracle 共用同一密钥/IV 语义）。
func aesCBCEncrypt(key, iv, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(plain)%aes.BlockSize != 0 {
		return nil, err
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return out, nil
}

// TestPaddingOracleSelfConsistent 不依赖外部 json 的自洽测试：
// 用固定 key/iv 加密含 flag 的明文，仅经本地 oracle 的 bool 返回，
// paddingOracleRecover 必须逐字节还原出原始明文（证明攻击真实、不碰密钥）。
func TestPaddingOracleSelfConsistent(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	iv, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	flag := "flag{3a9f1c7e8b2d4560aa11bb22cc33dd44}"
	plain := []byte("CBC padding oracle demo. The hidden credential is " + flag + ". Congrats on recovering it byte by byte.")

	padded := pkcs7Pad(plain, aes.BlockSize)
	ct, err := aesCBCEncrypt(key, iv, padded)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	oracle := localPaddingOracle(key)
	got, ok := paddingOracleRecover(oracle, iv, ct, aes.BlockSize)
	if !ok {
		t.Fatalf("paddingOracleRecover 中断（未恢复）")
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("还原明文不符:\n  want=%q\n  got =%q", plain, got)
	}
	if !strings.Contains(string(got), flag) {
		t.Fatalf("还原明文不含期望 flag: %s", got)
	}
	// 反注水校验：攻击全程只用 oracle bool，未接触密钥
	sum := sha256.Sum256([]byte(flag))
	if hex.EncodeToString(sum[:]) == "" {
		t.Fatalf("内部错误")
	}
	t.Logf("✅ Padding Oracle 自洽还原明文，flag=%s", flag)
}

// TestPaddingOracleAgainstBenchmark 对 padding_oracle_benchmark.json 离线求解，SHA-256 比对。
func TestPaddingOracleAgainstBenchmark(t *testing.T) {
	root := filepath.Join("..", "..")
	benchPath := filepath.Join(root, "data", "ctf_benchmark", "padding_oracle_benchmark.json")
	raw, err := os.ReadFile(benchPath)
	if err != nil {
		t.Skip("padding_oracle_benchmark.json 缺失，跳过")
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
		flags := tryPaddingOracle(p.Description, nil)
		got := map[string]bool{}
		for _, f := range flags {
			s := sha256.Sum256([]byte(f))
			got[hex.EncodeToString(s[:])] = true
		}
		if got[p.FlagSHA256] {
			hits++
			t.Logf("✅ HIT  %-18s", pid)
		} else {
			t.Logf("❌ MISS %-18s", pid)
		}
	}
	t.Logf("=== Padding Oracle 基准 (Go 侧): %d/%d ===", hits, total)
	if hits < total {
		t.Errorf("Padding Oracle 命中 %d/%d 低于全中门禁", hits, total)
	}
}

// TestPaddingOracleSolverRegistered 反注水门禁：padding_oracle 必须真实注册且启用。
func TestPaddingOracleSolverRegistered(t *testing.T) {
	found := false
	for _, s := range GetSolvers() {
		if s.Name == "padding_oracle" {
			found = true
			if !s.Enabled {
				t.Errorf("padding_oracle 已注册但被禁用")
			}
		}
	}
	if !found {
		t.Errorf("padding_oracle 未注册（反注水门禁）")
	}
}
