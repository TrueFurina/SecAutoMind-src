package ctfplatform

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// TestMD5ManualMatchesStdlib 验证手动 MD5 压缩/填充/finalize 与标准库逐字节一致。
func TestMD5ManualMatchesStdlib(t *testing.T) {
	iv := [4]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}
	cases := []string{
		"", "abc", "a", "ab", "x",
		strings.Repeat("x", 55), strings.Repeat("y", 56),
		strings.Repeat("z", 63), strings.Repeat("w", 64), strings.Repeat("q", 100),
		"The quick brown fox jumps over the lazy dog",
	}
	for _, s := range cases {
		ref := md5.Sum([]byte(s))
		msg := append([]byte(s), mgGluePadding(len(s), 64, "md5")...)
		st := iv
		for off := 0; off < len(msg); off += 64 {
			st = md5Compress(st, msg[off:off+64])
		}
		got := md5DigestFromState(st)
		if !bytes.Equal(got, ref[:]) {
			t.Fatalf("MD5 manual mismatch for %q\n got %x\nwant %x", s, got, ref[:])
		}
	}
}

// TestSHA1ManualMatchesStdlib 验证手动 SHA1 压缩/填充/finalize 与标准库逐字节一致。
func TestSHA1ManualMatchesStdlib(t *testing.T) {
	cases := []string{
		"", "abc", "a", strings.Repeat("x", 55), strings.Repeat("y", 64),
		strings.Repeat("z", 100), "The quick brown fox jumps over the lazy dog",
	}
	for _, s := range cases {
		ref := sha1.Sum([]byte(s))
		msg := append([]byte(s), mgGluePadding(len(s), 64, "sha1")...)
		st := sha1Init
		for off := 0; off < len(msg); off += 64 {
			st = sha1Compress(st, msg[off:off+64])
		}
		got := sha1DigestFromState(st)
		if !bytes.Equal(got, ref[:]) {
			t.Fatalf("SHA1 manual mismatch for %q\n got %x\nwant %x", s, got, ref[:])
		}
	}
}

// serverMAC 模拟只知 secret 的服务端：H(secret || msg)。
func serverMAC(algo string, secret, msg []byte) []byte {
	buf := append(append([]byte{}, secret...), msg...)
	if algo == "sha1" {
		sum := sha1.Sum(buf)
		return sum[:]
	}
	sum := md5.Sum(buf)
	return sum[:]
}

// TestHashLengthExtensionMD5 真实攻击：已知 data+MAC，伪造含 extra 的消息，
// 其 MAC 能在只知 secret 的服务端通过校验——全程不接触 secret。
func TestHashLengthExtensionMD5(t *testing.T) {
	secret := []byte("flag{sup3r_s3cr3t_l3ngth_ext}")
	knownData := []byte("user=guest")
	extra := []byte(";role=admin")
	knownMAC := serverMAC("md5", secret, knownData)

	forgedMsg, forgedMAC, ok := hashLengthExtend("md5", knownMAC, knownData, extra, len(secret))
	if !ok {
		t.Fatal("hashLengthExtend failed")
	}
	ref := serverMAC("md5", secret, forgedMsg)
	if !bytes.Equal(ref, forgedMAC) {
		t.Fatalf("forged MAC rejected by server\n got %x\nwant %x", forgedMAC, ref)
	}
	if !bytes.Contains(forgedMsg, extra) {
		t.Fatal("extra data missing in forged message")
	}
	if bytes.Equal(forgedMsg, knownData) {
		t.Fatal("forged message equals known data (no extension)")
	}
	t.Logf("✅ MD5 长度扩展：forged_mac=%s 服务端校验通过", hex.EncodeToString(forgedMAC))
}

func TestHashLengthExtensionSHA1(t *testing.T) {
	secret := []byte("flag{sh4_1s_n0t_s4f3_4nym0r3}")
	knownData := []byte("role=user")
	extra := []byte("&admin=1")
	knownMAC := serverMAC("sha1", secret, knownData)

	forgedMsg, forgedMAC, ok := hashLengthExtend("sha1", knownMAC, knownData, extra, len(secret))
	if !ok {
		t.Fatal("hashLengthExtend failed")
	}
	ref := serverMAC("sha1", secret, forgedMsg)
	if !bytes.Equal(ref, forgedMAC) {
		t.Fatalf("forged MAC rejected by server\n got %x\nwant %x", forgedMAC, ref)
	}
	t.Logf("✅ SHA1 长度扩展：forged_mac=%s 服务端校验通过", hex.EncodeToString(forgedMAC))
}

// TestHashLengthExtensionSolverParses 验证从题目描述文本解析并发动攻击。
func TestHashLengthExtensionSolverParses(t *testing.T) {
	secret := []byte("flag{sup3r_s3cr3t_l3ngth_ext}")
	knownData := []byte("user=guest")
	extra := []byte(";role=admin")
	knownMAC := serverMAC("md5", secret, knownData)

	desc := fmt.Sprintf(
		"Task: this endpoint uses HMAC-like check MAC=MD5(secret||data); perform a length extension attack.\n"+
			"known_hash=%s\nknown_message=%s\nappend=%s\nsecret_length=%d\n",
		hex.EncodeToString(knownMAC), knownData, extra, len(secret))

	got := tryHashLengthExtension(desc, nil)
	if len(got) == 0 {
		t.Fatal("solver returned no candidates")
	}
	// 期望的伪造 MAC 由内部函数算出，必须出现在候选中
	_, wantMAC, ok := hashLengthExtend("md5", knownMAC, knownData, extra, len(secret))
	if !ok {
		t.Fatal("internal extend failed")
	}
	wantHex := hex.EncodeToString(wantMAC)
	found := false
	for _, c := range got {
		if c == wantHex {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected forged MAC %s not in solver output %v", wantHex, got)
	}
	t.Logf("✅ 求解器解析文本并发动攻击，命中 forged_mac=%s", wantHex)
}

// TestHashLengthExtensionSolverRegistered 反注水门禁：求解器必须真实注册到注册表。
func TestHashLengthExtensionSolverRegistered(t *testing.T) {
	found := false
	for _, s := range GetSolvers() {
		if s.Name == "hash_length_extension" {
			found = true
			if s.Solver == nil {
				t.Fatal("registered solver has nil function")
			}
		}
	}
	if !found {
		t.Fatal("hash_length_extension not registered")
	}
}
