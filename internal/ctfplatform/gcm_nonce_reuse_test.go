package ctfplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// gcmNRScenario 构造一个 nonce 复用的场景：固定 keystream（同 nonce → 同 CTR keystream），
// m1(已知) 与 m2(flag) 共享。返回 (nonce, ct1, known, ct2, secret)。
func gcmNRScenario(t *testing.T) (nonce, ct1, known, ct2, secret []byte) {
	t.Helper()
	nonce = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc}
	ks := make([]byte, 96) // 固定 keystream（同 nonce → 同 CTR keystream）
	for i := range ks {
		ks[i] = byte(i)
	}
	known = []byte("The quick brown fox jumps over the lazy dog. KNOWN_PREFIX_PADDING_AA")
	secret = []byte("flag{gcm_nonce_reuse_keystream_recovered_2026}")
	if len(ks) < len(known) || len(ks) < len(secret) {
		t.Fatal("keystream 太短，场景构造非法")
	}
	ct1 = xorBytes(known, ks[:len(known)])
	ct2 = xorBytes(secret, ks[:len(secret)])
	return
}

func TestGCMNonceReuseBasic(t *testing.T) {
	nonce, ct1, known, ct2, secret := gcmNRScenario(t)
	desc := strings.Join([]string{
		"AES-GCM nonce reuse: same 256-bit key, same 96-bit nonce for two messages.",
		"nonce=" + hex.EncodeToString(nonce),
		"ct1=" + hex.EncodeToString(ct1),
		"known_plaintext=" + hex.EncodeToString(known),
		"ct2=" + hex.EncodeToString(ct2),
	}, "\n")
	cands := solveGCMNonceReuse(context.Background(), desc, nil)
	if len(cands) == 0 {
		t.Fatal("无候选输出")
	}
	if string(cands[0]) != string(secret) {
		t.Fatalf("复原明文不匹配: got %q want %q", cands[0], secret)
	}
}

func TestGCMNonceReuseSolverParses(t *testing.T) {
	// 用与基准集同款的 description 形态验证「读题解析」链路。
	nonce, ct1, known, ct2, secret := gcmNRScenario(t)
	desc := "AES-GCM with reused nonce. The two messages share one CTR keystream.\n" +
		"nonce=" + hex.EncodeToString(nonce) + "\n" +
		"ct1=" + hex.EncodeToString(ct1) + "\n" +
		"known_plaintext=" + hex.EncodeToString(known) + "\n" +
		"ct2=" + hex.EncodeToString(ct2) + "\n"
	cands := solveGCMNonceReuse(context.Background(), desc, nil)
	if len(cands) == 0 {
		t.Fatal("无候选输出")
	}
	got := sha256.Sum256([]byte(cands[0]))
	want := sha256.Sum256(secret)
	if got != want {
		t.Fatalf("SHA-256 不匹配: recovered=%q", cands[0])
	}
}

func TestGCMNonceReuseBlobFormat(t *testing.T) {
	// 完整 GCM blob 形态： nonce(12)‖ciphertext‖tag(16)。
	nonce, ct1, known, ct2, secret := gcmNRScenario(t)
	tag := make([]byte, 16)
	blob1 := append(append(append([]byte{}, nonce...), ct1...), tag...)
	blob2 := append(append(append([]byte{}, nonce...), ct2...), tag...)
	desc := "GCM nonce reuse (full blobs).\n" +
		"blob1=" + hex.EncodeToString(blob1) + "\n" +
		"known_plaintext=" + hex.EncodeToString(known) + "\n" +
		"blob2=" + hex.EncodeToString(blob2) + "\n"
	cands := solveGCMNonceReuse(context.Background(), desc, nil)
	if len(cands) == 0 {
		t.Fatal("无候选输出")
	}
	if string(cands[0]) != string(secret) {
		t.Fatalf("blob 形态复原不匹配: %q", cands[0])
	}
}

func TestGCMNonceReusePartialKnown(t *testing.T) {
	// 已知明文比 secret 短 → 仅能还原前缀（长度 = len(known)）。
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	ks := make([]byte, 96)
	for i := range ks {
		ks[i] = byte(i)
	}
	known := []byte("short known")
	secret := []byte("flag{partial_known_plaintext_recovers_prefix_only_xxxx}")
	if len(ks) < len(secret) {
		t.Fatal("keystream 太短")
	}
	ct1 := xorBytes(known, ks[:len(known)])
	ct2 := xorBytes(secret, ks[:len(secret)])
	desc := "same nonce gcm.\n" +
		"nonce=" + hex.EncodeToString(nonce) + "\n" +
		"ct1=" + hex.EncodeToString(ct1) + "\n" +
		"known_plaintext=" + hex.EncodeToString(known) + "\n" +
		"ct2=" + hex.EncodeToString(ct2) + "\n"
	cands := solveGCMNonceReuse(context.Background(), desc, nil)
	if len(cands) == 0 {
		t.Fatal("无候选输出")
	}
	got := []byte(cands[0])
	if string(got) != string(secret[:len(known)]) {
		t.Fatalf("前缀复原不匹配: got %q want %q", got, secret[:len(known)])
	}
}

func TestGCMNonceReuseSolverRegistered(t *testing.T) {
	// 反注水门禁：gcm_nonce_reuse 必须真实注册且启用。
	found := false
	enabled := false
	for _, s := range GetSolvers() {
		if s.Name == "gcm_nonce_reuse" {
			found = true
			enabled = s.Enabled
			break
		}
	}
	if !found {
		t.Fatal("gcm_nonce_reuse 未注册（反注水门禁）")
	}
	if !enabled {
		t.Fatal("gcm_nonce_reuse 已注册但被禁用")
	}
}
