package ctfplatform

// des_crypt.go —— 传统 Unix crypt(3) 的 DES 变体（13 字符口令哈希）纯 Go 实现。
//
// 为什么自己实现：靶场的 /restricted/.htpasswd 里是 DES-crypt 哈希，
// 破解需要「对候选口令做同样的哈希再比对」。本机与服务器都没有 john/hashcat，
// 而引入外部依赖会破坏"离线可复现"。故按 FIPS 46 表实现，并用参考实现
// （Linux 的 crypt(3)，经 python crypt 模块）逐条校准——见 des_crypt_test.go 的 10 条向量。
//
// 与标准 DES 的差异（crypt(3) 特有）：
//   1. 密钥调度只算一次，25 轮迭代复用同一组子密钥（削弱版 DES）；
//   2. 2 字符盐的低 8 位会**交换 E 扩展表每组 6 位中的前两位**；
//   3. 初始块为全 0，迭代 25 次后按 6 位分组编码成 11 字符。

// cryptAlphabet 是 crypt(3) 的输出字母表。
const cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var (
	desIP = [64]int{
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7,
	}
	desFP = [64]int{
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41, 9, 49, 17, 57, 25,
	}
	desE = [48]int{
		32, 1, 2, 3, 4, 5,
		4, 5, 6, 7, 8, 9,
		8, 9, 10, 11, 12, 13,
		12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21,
		20, 21, 22, 23, 24, 25,
		24, 25, 26, 27, 28, 29,
		28, 29, 30, 31, 32, 1,
	}
	desP = [32]int{
		16, 7, 20, 21, 29, 12, 28, 17,
		1, 15, 23, 26, 5, 18, 31, 10,
		2, 8, 24, 14, 32, 27, 3, 9,
		19, 13, 30, 6, 22, 11, 4, 25,
	}
	desPC1 = [56]int{
		57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27,
		19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4,
	}
	desPC2 = [48]int{
		14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
		23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
		41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
	}
	desShifts = [16]int{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}

	desSBox = [8][64]uint32{
		{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
			0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
			4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
			15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
		{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
			3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
			0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
			13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
		{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
			13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
			13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
			1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
		{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
			13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
			10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
			3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
		{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
			14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
			4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
			11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
		{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
			10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
			9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
			4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
		{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
			13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
			1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
			6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
		{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
			1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
			7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
			2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
	}
)

// desPermute 按 table 从 in 中取位，输出紧凑排列到高位。
// inBits 是输入位宽（table 里的位号从 1 开始，1 = 最高位）。
func desPermute(in uint64, table []int, inBits int) uint64 {
	var out uint64
	n := len(table)
	for i, p := range table {
		bit := (in >> uint(inBits-p)) & 1
		out |= bit << uint(n-1-i)
	}
	return out
}

// desRotate28 对 28 位值左循环移位。
func desRotate28(v uint32, n int) uint32 {
	return ((v << uint(n)) | (v >> uint(28-n))) & 0x0fffffff
}

// desSubkeys 由 8 字节口令生成 16 组 48 位子密钥（crypt(3) 只算一次并复用）。
func desSubkeys(key [8]byte) [16]uint64 {
	var k64 uint64
	for i := 0; i < 8; i++ {
		k64 = (k64 << 8) | uint64(key[i])
	}
	k56 := desPermute(k64, desPC1[:], 64)
	c := uint32(k56>>28) & 0x0fffffff
	d := uint32(k56) & 0x0fffffff
	var out [16]uint64
	for i := 0; i < 16; i++ {
		c = desRotate28(c, desShifts[i])
		d = desRotate28(d, desShifts[i])
		cd := (uint64(c) << 28) | uint64(d)
		out[i] = desPermute(cd, desPC2[:], 56)
	}
	return out
}

// desFeistel 是单轮 f 函数：E 扩展（可被盐改写）→ 异或子密钥 → S 盒 → P 置换。
func desFeistel(r uint32, subkey uint64, eTable []int) uint32 {
	e := desPermute(uint64(r), eTable, 32) ^ subkey
	var out uint32
	for i := 0; i < 8; i++ {
		six := (e >> uint(42-6*i)) & 0x3f
		row := ((six >> 4) & 2) | (six & 1)
		col := (six >> 1) & 0x0f
		out |= desSBox[i][row*16+col] << uint(28-4*i)
	}
	return uint32(desPermute(uint64(out), desP[:], 32))
}

// desEncryptBlock 执行一次完整 DES 加密（16 轮）。
func desEncryptBlock(block uint64, subkeys [16]uint64, eTable []int) uint64 {
	ip := desPermute(block, desIP[:], 64)
	l := uint32(ip >> 32)
	r := uint32(ip)
	for i := 0; i < 16; i++ {
		l, r = r, l^desFeistel(r, subkeys[i], eTable)
	}
	return desPermute((uint64(r)<<32)|uint64(l), desFP[:], 64)
}

// cryptSaltValue 把 2 字符盐换算成 crypt 用的位值。
// 注意顺序：musl/FreeBSD 实现是 (bin(s[1]) << 6) | bin(s[0])，不是正序拼接。
func cryptSaltValue(salt string) uint32 {
	bin := func(c byte) uint32 {
		for i := 0; i < len(cryptAlphabet); i++ {
			if cryptAlphabet[i] == c {
				return uint32(i)
			}
		}
		return 0
	}
	var a, b uint32
	if len(salt) > 0 {
		a = bin(salt[0])
	}
	if len(salt) > 1 {
		b = bin(salt[1])
	}
	return (b << 6) | a
}

// desCrypt 计算 crypt(3) DES 哈希（13 字符，前 2 位是盐）。
//
// 实现依据：musl src/crypt/crypt_des.c（源自 FreeSec / Solar Designer），
// 与标准 DES 的差异全部在此复刻：
//   - 口令每字节左移 1 位（7-bit 密钥，奇偶位为 0）；
//   - 盐值 = (bin(s[1])<<6)|bin(s[0])，第 i 位对应掩码第 (23-i) 位；
//   - 轮函数里 f=(r48l^r48r)&saltbits，等价于交换 E 输出的第 p 位与第 p+24 位；
//   - 全 0 块迭代 25 次（IP 只做一次、FP 只做一次）；
//   - 输出按 MSB 优先的 6 位分组编码成 11 字符。
func desCrypt(password, salt string) string {
	if len(salt) > 2 {
		salt = salt[:2]
	}
	saltVal := cryptSaltValue(salt)

	// 盐位 → E 输出交换对：salt 第 i 位置位 ⇒ 交换 E 输出第 i 位与第 i+24 位
	// （musl 用 saltbits 第 (23-i) 位掩码实现，因 r48l 高位才是 E 的第 0 组，
	//   换算后等价于 i ↔ i+24，已用 10 条参考向量校准）
	eTable := make([]int, 48)
	copy(eTable, desE[:])
	for i := 0; i < 12; i++ {
		if saltVal&(1<<uint(i)) == 0 {
			continue
		}
		eTable[i], eTable[i+24] = eTable[i+24], eTable[i]
	}

	// 口令 → 8 字节密钥：每字节左移 1 位（丢弃最高位，奇偶位为 0）
	var key [8]byte
	for i := 0; i < 8 && i < len(password); i++ {
		key[i] = password[i] << 1
	}
	subkeys := desSubkeys(key)

	// 全 0 块迭代 25 次
	var block uint64
	for i := 0; i < 25; i++ {
		block = desEncryptBlock(block, subkeys, eTable)
	}

	// 编码：MSB 优先的 6 位分组（严格照 musl 的位表达式）
	r0 := uint32(block >> 32)
	r1 := uint32(block)
	var out [13]byte
	out[0], out[1] = salt[0], salt[1]
	idx := 2

	l := r0 >> 8
	out[idx] = cryptAlphabet[(l>>18)&0x3f]
	idx++
	out[idx] = cryptAlphabet[(l>>12)&0x3f]
	idx++
	out[idx] = cryptAlphabet[(l>>6)&0x3f]
	idx++
	out[idx] = cryptAlphabet[l&0x3f]
	idx++

	l = (r0 << 16) | ((r1 >> 16) & 0xffff)
	out[idx] = cryptAlphabet[(l>>18)&0x3f]
	idx++
	out[idx] = cryptAlphabet[(l>>12)&0x3f]
	idx++
	out[idx] = cryptAlphabet[(l>>6)&0x3f]
	idx++
	out[idx] = cryptAlphabet[l&0x3f]
	idx++

	l = r1 << 2
	out[idx] = cryptAlphabet[(l>>12)&0x3f]
	idx++
	out[idx] = cryptAlphabet[(l>>6)&0x3f]
	idx++
	out[idx] = cryptAlphabet[l&0x3f]
	idx++

	return string(out[:idx])
}
