// padding_oracle.go —— 真实 CBC Padding Oracle 攻击（消除"关键词占位"注水嫌疑）。
//
// 经典 PKCS#7 CBC padding oracle 攻击：攻击者仅能向 oracle 询问"这段密文
// 解密后 PKCS#7 填充是否合法"（bool），即可逐字节还原明文，无需密钥。
// 与 ECDSA nonce 复用同理：把"只识别关键词返回提示"升级为"真实执行攻击产出 flag"。
//
// 双语言机验：Go 实现见本文件；Python 侧镜像见 data/ctf_benchmark/judge_padding_oracle.py。
package ctfplatform

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// pkcs7Valid 校验数据是否符合 PKCS#7 填充（CBC padding oracle 的核心判定）。
// 末字节 p∈[1,bs]，且末 p 字节全部等于 p。
func pkcs7Valid(padded []byte, blockSize int) bool {
	if len(padded) == 0 || len(padded)%blockSize != 0 {
		return false
	}
	p := int(padded[len(padded)-1])
	if p < 1 || p > blockSize {
		return false
	}
	for i := len(padded) - p; i < len(padded); i++ {
		if int(padded[i]) != p {
			return false
		}
	}
	return true
}

// pkcs7Unpad 去除 PKCS#7 填充；非法返回 (data, false) 仍原样返回。
func pkcs7Unpad(data []byte, blockSize int) ([]byte, bool) {
	if !pkcs7Valid(data, blockSize) {
		return data, false
	}
	p := int(data[len(data)-1])
	return data[:len(data)-p], true
}

// pkcs7Pad 对数据做 PKCS#7 填充至 blockSize 的倍数（测试与靶场构造用）。
func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// aesCBCDecrypt 用 AES-CBC 解密（纯标准库），iv 长度须为 blockSize，body 须为 blockSize 倍数。
func aesCBCDecrypt(key, iv, body []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize || len(body) == 0 || len(body)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("AES-CBC 参数非法: iv=%d body=%d", len(iv), len(body))
	}
	plain := make([]byte, len(body))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, body)
	return plain, nil
}

// localPaddingOracle 构造本地确定性 oracle：收到整段密文 ct（ct[0:bs] 作 IV，
// ct[bs:] 作 body），AES-CBC 解密后仅判定末块 PKCS#7 是否合法。
// 攻击算法只依赖其 bool 返回值，全程不接触密钥。
func localPaddingOracle(key []byte) func([]byte) bool {
	return func(ct []byte) bool {
		if len(ct) < aes.BlockSize*2 || len(ct)%aes.BlockSize != 0 {
			return false
		}
		pt, err := aesCBCDecrypt(key, ct[:aes.BlockSize], ct[aes.BlockSize:])
		if err != nil {
			return false
		}
		return pkcs7Valid(pt, aes.BlockSize)
	}
}

// paddingOracleRecover 经典 PKCS#7 CBC Padding Oracle 攻击：
// 仅凭 oracle(ct)->bool 这个黑盒，逐字节还原明文，无需密钥。
//
//   - oracle: 输入「IV(bs)||C(>=1 block)」整段密文，返回末块填充是否合法
//   - iv:     真实 IV（首块密文）
//   - ct:     真实密文（C1||C2||...||Cm，不含 IV）
//   - bs:     分组长度（AES=16）
//
// 对每块 C_i 以伪造前缀 prefix 顶替 C_{i-1}，逐字节逼出中间状态 I_i=D(C_i)，
// 再 P_i = I_i XOR C_{i-1} 得明文；末块去填充。
// 成功返回 (明文, true)，oracle 不可用或攻击中断返回 (nil, false)。
func paddingOracleRecover(oracle func([]byte) bool, iv, ct []byte, bs int) ([]byte, bool) {
	if oracle == nil || len(ct) == 0 || len(ct)%bs != 0 || len(iv) != bs {
		return nil, false
	}
	full := append(append([]byte{}, iv...), ct...)
	blocks := make([][]byte, 0, len(full)/bs+1)
	for i := 0; i < len(full); i += bs {
		blocks = append(blocks, full[i:i+bs])
	}
	if len(blocks) < 2 {
		return nil, false
	}

	plain := make([]byte, 0, len(ct))
	for i := 1; i < len(blocks); i++ {
		target := blocks[i]
		realPrev := blocks[i-1]
		I := make([]byte, bs) // 中间状态 D(target)
		for b := bs - 1; b >= 0; b-- {
			padval := byte(bs - b)
			prefix := make([]byte, bs) // 伪造的 C_{i-1}
			for j := b + 1; j < bs; j++ {
				prefix[j] = I[j] ^ padval
			}
			// 末字节（b==bs-1）存在 0x01 / 0x02 伪命中歧义，用二次探测消歧：
			// 翻转 prefix[bs-2]，若 oracle 仍为真 → 真实填充是 0x01（接受）；
			// 否则 → 是 0x02 等更大填充或伪命中，记录为弱候选。
			p1, p2 := -1, -1
			for g := 0; g < 256; g++ {
				prefix[b] = byte(g)
				probe := append(append([]byte{}, prefix...), target...)
				if !oracle(probe) {
					continue
				}
				if b == bs-1 && bs >= 2 {
					p2b := append([]byte{}, prefix...)
					p2b[bs-2] ^= 0xFF
					probe2 := append(append([]byte{}, p2b...), target...)
					if oracle(probe2) {
						p1 = g // 强候选：真实填充 0x01
					} else {
						p2 = g // 弱候选：伪命中或真实更大填充
					}
				} else {
					p1 = g
				}
			}
			var g int
			switch {
			case p1 >= 0:
				g = p1
			case p2 >= 0:
				g = p2
			default:
				return nil, false
			}
			I[b] = byte(g) ^ padval
		}
		pblock := make([]byte, bs)
		for j := 0; j < bs; j++ {
			pblock[j] = I[j] ^ realPrev[j]
		}
		plain = append(plain, pblock...)
	}
	if unpadded, ok := pkcs7Unpad(plain, bs); ok {
		return unpadded, true
	}
	return plain, true
}

// tryPaddingOracle 真实攻击入口（替换原关键词占位）：
// 从题目描述/附件解析 aes_key 与 ciphertext（IV||CT 的 hex），构造本地 oracle
// 并运行 paddingOracleRecover 还原明文，扫描其中 flag。
//
// 离线合成基准（基准集给 key，纯确定性）与真实靶场（给 oracle_url 在线打）共用
// 同一套攻击算法；无参数时返回 nil（不制造误报）。
func tryPaddingOracle(text string, attachments map[string]string) []string {
	fullText := text
	for _, v := range attachments {
		fullText += "\n" + v
	}

	// 在线模式：若给了 oracle URL，构造 HTTP oracle 实打靶场（真实 CTF 路径）。
	if m := regexp.MustCompile(`(?i)padding_oracle_url\s*=\s*(\S+)`).FindStringSubmatch(fullText); m != nil {
		url := m[1]
		hexRe := regexp.MustCompile(`(?i)ciphertext\s*=\s*([0-9a-fA-F]+)`)
		cm := hexRe.FindStringSubmatch(fullText)
		if cm == nil {
			return nil
		}
		raw, err := hex.DecodeString(cm[1])
		if err != nil || len(raw) < aes.BlockSize*2 || len(raw)%aes.BlockSize != 0 {
			return nil
		}
		oracle := httpPaddingOracle(url)
		iv, ct := raw[:aes.BlockSize], raw[aes.BlockSize:]
		if plain, ok := paddingOracleRecover(oracle, iv, ct, aes.BlockSize); ok {
			if flags := scanFlags(string(plain)); len(flags) > 0 {
				return flags
			}
			return []string{"PaddingOracle解密(hex): " + hex.EncodeToString(plain)}
		}
		return nil
	}

	// 离线合成模式：aes_key + ciphertext（IV||CT）确定性恢复。
	keyRe := regexp.MustCompile(`(?i)aes_key\s*=\s*([0-9a-fA-F]+)`)
	ctRe := regexp.MustCompile(`(?i)ciphertext\s*=\s*([0-9a-fA-F]+)`)
	km := keyRe.FindStringSubmatch(fullText)
	cm := ctRe.FindStringSubmatch(fullText)
	if km == nil || cm == nil {
		return nil
	}
	key, err1 := hex.DecodeString(km[1])
	raw, err2 := hex.DecodeString(cm[1])
	if err1 != nil || err2 != nil || len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil
	}
	if len(raw) < aes.BlockSize*2 || len(raw)%aes.BlockSize != 0 {
		return nil
	}
	iv, ct := raw[:aes.BlockSize], raw[aes.BlockSize:]
	oracle := localPaddingOracle(key)
	if plain, ok := paddingOracleRecover(oracle, iv, ct, aes.BlockSize); ok {
		if flags := scanFlags(string(plain)); len(flags) > 0 {
			return flags
		}
		return []string{"PaddingOracle解密(hex): " + hex.EncodeToString(plain)}
	}
	return nil
}

// httpPaddingOracle 构造在线 oracle：POST hex(ct) 到 URL，响应含 "valid"/"1"/"true" 视为填充合法。
// 仅用于真实靶场，不进入离线基准（保持 CI 确定性）。
func httpPaddingOracle(url string) func([]byte) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	return func(ct []byte) bool {
		resp, err := client.Post(url, "application/x-www-form-urlencoded",
			strings.NewReader("ct="+hex.EncodeToString(ct)))
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		buf, _ := io.ReadAll(resp.Body)
		lower := strings.ToLower(string(buf))
		return strings.Contains(lower, "valid") || strings.Contains(lower, "true") || strings.Contains(lower, "\"1\"")
	}
}
