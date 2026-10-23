package ctfplatform

// ppk.go —— PuTTY .ppk 私钥解析与 PEM 转换。
//
// 背景：CTF4 靶机上 /home/achen/.ssh/achen_priv.ppk 是**未加密且全局可读**的私钥，
// 是说明书 Step 10「偷 SSH 私钥」的目标。Go 的 x/crypto/ssh 只吃 OpenSSH/PEM，
// 不认 PuTTY 格式，故在此实现 PPK v2 → RSA → PKCS#1 PEM 的转换。
//
// 支持范围：PuTTY-User-Key-File-2，且 Encryption: none。
// 加密的 PPK 一律明确报错（不静默返回空 key，避免误判为"解析成功但登录失败"）。

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
)

// ppkField 从 SSH wire 格式里读一个 length-prefixed 字段。
func ppkField(buf *bytes.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(buf, binary.BigEndian, &n); err != nil {
		return nil, fmt.Errorf("读取字段长度失败: %w", err)
	}
	if n > uint32(buf.Len()) {
		return nil, fmt.Errorf("字段长度越界: %d > %d", n, buf.Len())
	}
	out := make([]byte, n)
	if _, err := buf.Read(out); err != nil {
		return nil, fmt.Errorf("读取字段内容失败: %w", err)
	}
	return out, nil
}

// ppkMPInt 读一个 mpint（大端有符号整数，取正值）。
func ppkMPInt(buf *bytes.Reader) (*big.Int, error) {
	b, err := ppkField(buf)
	if err != nil {
		return nil, err
	}
	if len(b) > 0 && b[0]&0x80 != 0 {
		return nil, fmt.Errorf("mpint 为负数，非法 RSA 参数")
	}
	return new(big.Int).SetBytes(b), nil
}

// ParsePPK 解析未加密的 PuTTY v2 私钥，返回 RSA 私钥。
func ParsePPK(data []byte) (*rsa.PrivateKey, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")

	// 1. 头部
	var pubLines, privLines int
	version := ""
	encrypted := true // 默认按最坏情况处理
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(ln, "PuTTY-User-Key-File-"):
			version = strings.TrimPrefix(ln, "PuTTY-User-Key-File-")
			if i := strings.IndexByte(version, ':'); i > 0 {
				version = version[:i]
			}
		case strings.HasPrefix(ln, "Encryption:"):
			encrypted = !strings.Contains(strings.ToLower(ln), "none")
		case strings.HasPrefix(ln, "Public-Lines:"):
			fmt.Sscanf(strings.TrimPrefix(ln, "Public-Lines:"), "%d", &pubLines)
		case strings.HasPrefix(ln, "Private-Lines:"):
			fmt.Sscanf(strings.TrimPrefix(ln, "Private-Lines:"), "%d", &privLines)
		}
	}
	if version != "2" {
		return nil, fmt.Errorf("不支持的 PPK 版本 %q（仅支持 PuTTY-User-Key-File-2）", version)
	}
	if encrypted {
		return nil, fmt.Errorf("PPK 已加密，本实现不支持（需要口令）")
	}
	if pubLines <= 0 || privLines <= 0 {
		return nil, fmt.Errorf("PPK 头部不完整（Public-Lines=%d Private-Lines=%d）", pubLines, privLines)
	}

	// 2. 取出 Public-Lines / Private-Lines 两段 base64
	// 注意头部是 "Public-Lines: 4"（冒号后有空格），必须按前缀匹配，不能整行相等。
	collect := func(prefix string, n int) string {
		for i, ln := range lines {
			if strings.HasPrefix(strings.TrimSpace(ln), prefix) {
				var sb strings.Builder
				for j := i + 1; j <= i+n && j < len(lines); j++ {
					sb.WriteString(strings.TrimSpace(lines[j]))
				}
				return sb.String()
			}
		}
		return ""
	}
	pubB64 := collect("Public-Lines:", pubLines)
	privB64 := collect("Private-Lines:", privLines)

	pubRaw, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return nil, fmt.Errorf("公钥段 base64 解码失败: %w", err)
	}
	privRaw, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return nil, fmt.Errorf("私钥段 base64 解码失败: %w", err)
	}

	// 3. 公钥段：string "ssh-rsa" + mpint e + mpint n
	pb := bytes.NewReader(pubRaw)
	keyType, err := ppkField(pb)
	if err != nil {
		return nil, err
	}
	if string(keyType) != "ssh-rsa" {
		return nil, fmt.Errorf("不支持的密钥类型 %q（仅支持 ssh-rsa）", string(keyType))
	}
	e, err := ppkMPInt(pb)
	if err != nil {
		return nil, err
	}
	n, err := ppkMPInt(pb)
	if err != nil {
		return nil, err
	}

	// 4. 私钥段：mpint d, p, q, iqmp
	pr := bytes.NewReader(privRaw)
	d, err := ppkMPInt(pr)
	if err != nil {
		return nil, err
	}
	p, err := ppkMPInt(pr)
	if err != nil {
		return nil, err
	}
	q, err := ppkMPInt(pr)
	if err != nil {
		return nil, err
	}

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
		D:         d,
		Primes:    []*big.Int{p, q},
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("RSA 私钥自校验失败: %w", err)
	}
	key.Precompute()
	return key, nil
}

// PPKToPEM 把 PPK 转成 PKCS#1 PEM（x/crypto/ssh 可直接解析）。
func PPKToPEM(data []byte) ([]byte, error) {
	key, err := ParsePPK(data)
	if err != nil {
		return nil, err
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), nil
}
