package ctfplatform

// CRC64 线性性伪造（Go 侧镜像，对齐 data/ctf_benchmark/judge_crc64.py）。
//
// 真题对照：CyberNova 2026 - Lazarus Phantom DB（crc_forgery_real 能力面）。
// 攻击本质：CRC 是 GF(2) 上的**线性**校验（不是 MAC）。对**等长**输入
//     crc(A ⊕ B) = crc(A) ⊕ crc(B)
// 于是多项式参数即使未知也能伪造：
//     1) /login 拿 guest 块的 crc；
//     2) Δ = guest ⊕ admin，拿 /oracle 学 crc(Δ)；
//     3) crc(admin) = crc(guest) ⊕ crc(Δ) → 提交伪造 cookie 通过完整性校验。
//
// 诚实设计（与 Python 靶场逐参数一致，勿单侧改动）：
//   - 多项式是**自定义值**（非标准 ECMA/ISO），标准库算不出 → 必须走 oracle 学；
//   - INIT/XOROUT 置 0，才使 crc 成为严格线性映射（否则有仿射偏移，线性性不成立）；
//   - flag 只在「data 精确等于 admin 块 且 crc 校验通过」时返回 —— 没有关键词可猜。

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// crc64Poly 自定义多项式（refin=false, refout=false 的长除法形态）。
// 与 live_target/crc64_range.py 的 POLY 必须逐位相同，否则双语言会各算各的。
const crc64Poly uint64 = 0x1AD3D94CBCA9B8F1

// 16 字节等长块：只有等长才能用异或翻转伪造（不等长时 CRC 的线性性不适用于前缀差异）。
var (
	crc64GuestBlock = []byte("user=guest\x00\x00\x00\x00\x00\x00")
	crc64AdminBlock = []byte("user=admin\x00\x00\x00\x00\x00\x00")
)

// crc64Custom 逐 bit 长除法实现自定义 CRC64（INIT=XOROUT=0 → 严格线性）。
func crc64Custom(data []byte) uint64 {
	var crc uint64
	for _, b := range data {
		crc ^= uint64(b) << 56
		for i := 0; i < 8; i++ {
			if crc&(1<<63) != 0 {
				crc = (crc << 1) ^ crc64Poly
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// crc64JSONGet 取 JSON（靶场全部端点为 JSON）。失败返回空 map，不 panic。
func crc64JSONGet(ctx context.Context, u string) map[string]interface{} {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// crc64BitflipAttack 对靶场执行线性性伪造，返回拿到的 flag（空串 = 未打通）。
//
// 返回 error 只在参数/编码层面（说明"没打成"），业务失败（403/无 flag）返回空串，
// 便于调用方区分"攻击没成功"与"靶场不可达"。
func crc64BitflipAttack(ctx context.Context, baseURL string) (string, error) {
	if len(crc64GuestBlock) != len(crc64AdminBlock) {
		return "", fmt.Errorf("guest/admin 块长度不等（%d vs %d），异或翻转不成立",
			len(crc64GuestBlock), len(crc64AdminBlock))
	}

	// 1) guest cookie
	login := crc64JSONGet(ctx, baseURL+"/login")
	if login == nil {
		return "", fmt.Errorf("靶场 /login 不可达")
	}
	guestCRCHex, _ := login["crc"].(string)
	guestCRC, err := parseHexU64(guestCRCHex)
	if err != nil {
		return "", fmt.Errorf("/login 返回的 crc 无法解析: %q", guestCRCHex)
	}

	// 2) 学 Δ 的 crc 贡献（Δ = guest ⊕ admin）
	delta := make([]byte, len(crc64GuestBlock))
	for i := range crc64GuestBlock {
		delta[i] = crc64GuestBlock[i] ^ crc64AdminBlock[i]
	}
	oracle := crc64JSONGet(ctx, baseURL+"/oracle?data="+hex.EncodeToString(delta))
	if oracle == nil {
		return "", fmt.Errorf("靶场 /oracle 不可达")
	}
	deltaCRCHex, _ := oracle["crc"].(string)
	deltaCRC, err := parseHexU64(deltaCRCHex)
	if err != nil {
		return "", fmt.Errorf("/oracle 返回的 crc 无法解析: %q", deltaCRCHex)
	}

	// 3) 线性性：crc(admin) = crc(guest) ⊕ crc(Δ)
	adminCRC := guestCRC ^ deltaCRC

	// 4) 提交伪造 cookie：<hex(data)>.<16 位 hex crc>
	cookie := hex.EncodeToString(crc64AdminBlock) + "." + fmt.Sprintf("%016x", adminCRC)
	resp := crc64JSONGet(ctx, baseURL+"/admin?cookie="+url.QueryEscape(cookie))
	if resp == nil {
		return "", fmt.Errorf("靶场 /admin 不可达")
	}
	ok, _ := resp["ok"].(bool)
	flag, _ := resp["flag"].(string)
	if !ok || flag == "" {
		msg, _ := resp["msg"].(string)
		return "", fmt.Errorf("伪造 cookie 未通过（%s）", msg)
	}
	return flag, nil
}

// parseHexU64 解析 16 位 hex CRC。
func parseHexU64(s string) (uint64, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return 0, err
	}
	if len(raw) > 8 {
		return 0, fmt.Errorf("crc 长度 %d 字节超过 8", len(raw))
	}
	var v uint64
	for _, b := range raw {
		v = v<<8 | uint64(b)
	}
	return v, nil
}
