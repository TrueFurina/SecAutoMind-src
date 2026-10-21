package ctfplatform

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// ppkFieldBytes 写一个 SSH wire 字段（4 字节长度 + 内容）。
func ppkFieldBytes(b []byte) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(len(b)))
	buf.Write(b)
	return buf.Bytes()
}

// ppkMPIntBytes 写一个 mpint（正数需前置 0x00 防被当负数）。
func ppkMPIntBytes(i *big.Int) []byte {
	b := i.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return ppkFieldBytes(b)
}

// encodePPKv2 把 RSA 私钥编码成 PuTTY v2 PPK（Encryption: none）。
// 仅供测试构造夹具；MAC 段写占位符（解析器不校验 MAC，真实使用中应校验）。
func encodePPKv2(key *rsa.PrivateKey) []byte {
	var pub bytes.Buffer
	pub.Write(ppkFieldBytes([]byte("ssh-rsa")))
	pub.Write(ppkMPIntBytes(big.NewInt(int64(key.E))))
	pub.Write(ppkMPIntBytes(key.N))

	var priv bytes.Buffer
	priv.Write(ppkMPIntBytes(key.D))
	priv.Write(ppkMPIntBytes(key.Primes[0]))
	priv.Write(ppkMPIntBytes(key.Primes[1]))
	priv.Write(ppkMPIntBytes(new(big.Int).ModInverse(key.Primes[1], key.Primes[0])))

	wrap := func(b []byte) (string, int) {
		s := base64.StdEncoding.EncodeToString(b)
		var lines []string
		for len(s) > 64 {
			lines = append(lines, s[:64])
			s = s[64:]
		}
		if len(s) > 0 {
			lines = append(lines, s)
		}
		return strings.Join(lines, "\n"), len(lines)
	}
	pubStr, pubN := wrap(pub.Bytes())
	privStr, privN := wrap(priv.Bytes())

	return []byte(fmt.Sprintf(
		"PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: test\nPublic-Lines: %d\n%s\nPrivate-Lines: %d\n%s\nPrivate-MAC: 0000000000000000000000000000000000000000\n",
		pubN, pubStr, privN, privStr))
}

func TestParsePPK_RoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	data := encodePPKv2(key)

	got, err := ParsePPK(data)
	if err != nil {
		t.Fatalf("ParsePPK 报错: %v", err)
	}
	if got.N.Cmp(key.N) != 0 || got.D.Cmp(key.D) != 0 || got.E != key.E {
		t.Fatal("解析出的 RSA 参数与原私钥不一致")
	}
	if len(got.Primes) != 2 || got.Primes[0].Cmp(key.Primes[0]) != 0 {
		t.Fatal("素数分量不一致")
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("解析结果自校验失败: %v", err)
	}
}

func TestPPKToPEM_ParsableBySSH(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := PPKToPEM(encodePPKv2(key))
	if err != nil {
		t.Fatalf("PPKToPEM 报错: %v", err)
	}
	if !strings.Contains(string(pemBytes), "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("PEM 头不符: %q", string(pemBytes[:40]))
	}
	// 用 x/crypto/ssh 这个独立消费方验证：能解析且公钥与原始公钥一致
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ssh.ParsePrivateKey 失败: %v", err)
	}
	wantPub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), wantPub.Marshal()) {
		t.Fatal("转换后公钥与原公钥不一致")
	}
	// 与直接用 x509 编出的 PKCS#1 PEM 逐字节一致（独立路径对照，不是自己跟自己比）
	wantPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if !bytes.Equal(pemBytes, wantPEM) {
		t.Fatal("PPKToPEM 与 x509.MarshalPKCS1PrivateKey 结果不一致")
	}
}

func TestParsePPK_RejectsEncrypted(t *testing.T) {
	data := []byte("PuTTY-User-Key-File-2: ssh-rsa\nEncryption: aes256-cbc\nComment: x\nPublic-Lines: 1\nAAAA\nPrivate-Lines: 1\nAAAA\n")
	if _, err := ParsePPK(data); err == nil {
		t.Fatal("加密的 PPK 应报错")
	} else if !strings.Contains(err.Error(), "加密") {
		t.Errorf("错误信息应说明加密，实际: %v", err)
	}
}

func TestParsePPK_RejectsUnsupportedVersion(t *testing.T) {
	data := []byte("PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nPublic-Lines: 1\nAAAA\nPrivate-Lines: 1\nAAAA\n")
	if _, err := ParsePPK(data); err == nil {
		t.Fatal("v3 应报不支持")
	}
}

func TestParsePPK_RejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "hello world", "PuTTY-User-Key-File-2: ssh-rsa\n"} {
		if _, err := ParsePPK([]byte(in)); err == nil {
			t.Errorf("垃圾输入 %q 应报错", in)
		}
	}
}

func TestParsePPK_RejectsNonRSA(t *testing.T) {
	// 公钥段声明 ssh-dss
	var pub bytes.Buffer
	pub.Write(ppkFieldBytes([]byte("ssh-dss")))
	pub.Write(ppkMPIntBytes(big.NewInt(23)))
	pub.Write(ppkMPIntBytes(big.NewInt(1024)))
	data := []byte(fmt.Sprintf("PuTTY-User-Key-File-2: ssh-dss\nEncryption: none\nPublic-Lines: 1\n%s\nPrivate-Lines: 1\nAAAA\n",
		base64.StdEncoding.EncodeToString(pub.Bytes())))
	if _, err := ParsePPK(data); err == nil {
		t.Fatal("非 ssh-rsa 应报错")
	}
}
