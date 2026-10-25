package ctfplatform

// presolve_const_compare.go —— 静态逆向「常量比对」型 flag 求解
// （xhlj_legacy skills/rev_const_compare.py Go 化，刀锋账本 #2）。
//
// 适用题型：二进制把用户输入经一次可逆变换后与内嵌常量数组比对。三类变换：
//   1. xor_const    —— 输入 XOR 单字节常量后 strcmp 常量数组（CSAW2023 whataxor）
//   2. subst_table  —— 2 字节/项替换表逐字节映射后 strncmp（CSAW2017 tablez）
//   3. tree_index   —— 常量数组为二叉查找树，比对「字符在树中的下标」（CSAW2019 beleaf）
//
// 管线：objdump -d -M intel（外部工具，fail-closed）→ 函数切分 → 栈上常量数组
// 提取（movabs 紧邻守卫 + 最长连续段）→ 三检测器出候选 → sha256/flag 形态把关。
// 诚实口径：只做确定性静态求解，不可外推到通用逆向。参考实现 342 行 python，
// 本移植用 debug/elf（stdlib）替代手写段表解析，objdump 文本正则逐条对齐。

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ── objdump 外部工具适配（与 upx/bkcrack 适配器同构）──

var ErrObjdumpUnavailable = errors.New("objdump 不可用（PATH 或 D:/miniconda3_new/Library/mingw-w64/bin）")

const objdumpDefaultTimeout = 90 * time.Second

var objdumpCandidates = []string{
	"objdump",
	`D:/miniconda3_new/Library/mingw-w64/bin/objdump.exe`,
	"objdump.exe",
}

var objdumpRunner = func(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func objdumpPath() (string, error) {
	for _, c := range objdumpCandidates {
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
	}
	return "", ErrObjdumpUnavailable
}

// objdumpDisasm 对临时落盘的附件执行 objdump（solve 语义：工具缺失 → ""）。
func objdumpDisasm(ctx context.Context, path string) string {
	tool, err := objdumpPath()
	if err != nil {
		return ""
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, objdumpDefaultTimeout)
	defer cancel()
	out, err := objdumpRunner(ctx, tool, "-d", "-M", "intel", path)
	if err != nil || out == "" {
		return ""
	}
	return out
}

// ── ELF 段表（debug/elf stdlib）──

type ccSection struct {
	name   string
	addr   uint64
	offset uint64
	size   uint64
}

func ccSections(path string) []ccSection {
	f, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []ccSection
	for _, s := range f.Sections {
		if s.Type != elf.SHT_PROGBITS && s.Type != elf.SHT_NOBITS {
			continue
		}
		if s.Addr == 0 || s.Size == 0 {
			continue
		}
		out = append(out, ccSection{name: s.Name, addr: s.Addr, offset: s.Offset, size: s.Size})
	}
	return out
}

func ccV2O(secs []ccSection, va uint64) (int, bool) {
	for _, s := range secs {
		if va >= s.addr && va < s.addr+s.size {
			return int(s.offset + (va - s.addr)), true
		}
	}
	return 0, false
}

func ccSecSpan(secs []ccSection, va uint64) (uint64, bool) {
	for _, s := range secs {
		if va >= s.addr && va < s.addr+s.size {
			return s.addr + s.size, true
		}
	}
	return 0, false
}

// ── 反汇编文本解析（正则与 python 版逐条对齐）──

var (
	ccSize        = map[string]int{"BYTE": 1, "WORD": 2, "DWORD": 4, "QWORD": 8}
	ccImmStoreRe  = regexp.MustCompile(`mov\s+(BYTE|WORD|DWORD|QWORD) PTR \[rbp-(0x[0-9a-f]+)\],(0x[0-9a-f]+)`)
	ccMovabsRe    = regexp.MustCompile(`movabs\s+(\w+),(0x[0-9a-f]+)`)
	ccMovR2SRe    = regexp.MustCompile(`mov\s+(BYTE|WORD|DWORD|QWORD) PTR \[rbp-(0x[0-9a-f]+)\],(\w+)`)
	ccXorImmRe    = regexp.MustCompile(`\bxor\s+al,(0x[0-9a-f]+)`)
	ccMovEsiRe    = regexp.MustCompile(`\bmov\s+esi,(0x[0-9a-f]+)`)
	ccLeaRipRe    = regexp.MustCompile(`lea\s+\w+,\[rip\+0x[0-9a-f]+\]\s+#\s+([0-9a-f]+)(?:\s+<([^>]+)>)?`)
	ccLeaScaleRe  = regexp.MustCompile(`lea\s+\w+,\[rax\*(4|8)\+0x0\]`)
	ccFuncHdrRe   = regexp.MustCompile(`^([0-9a-f]+) <([^>]+)>:`)
	ccCmpCallRe   = regexp.MustCompile(`call\s+[0-9a-f]+ <(strcmp|strncmp|memcmp)@plt>`)
	ccFlagShapeRe = regexp.MustCompile(`[A-Za-z0-9_]{1,12}\{[^}\s\x00-\x1f]{3,120}\}`)
	ccTblNameRe   = regexp.MustCompile(`tbl|tab|table|sbox|s_box`)
	ccRipAddrRe   = regexp.MustCompile(`#\s+([0-9a-f]+)`)
)

type ccFunc struct {
	name  string
	lines []string
}

func ccSplitFunctions(asm string) []ccFunc {
	var funcs []ccFunc
	var cur *ccFunc
	for _, line := range strings.Split(asm, "\n") {
		if m := ccFuncHdrRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			if cur != nil {
				funcs = append(funcs, *cur)
			}
			cur = &ccFunc{name: m[2]}
		} else if cur != nil {
			cur.lines = append(cur.lines, line)
		}
	}
	if cur != nil {
		funcs = append(funcs, *cur)
	}
	return funcs
}

func ccHexInt(s string) int {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	// 🔴 必须 ParseUint：movabs 64 位立即数常带最高位（如 0xb3be…），Sscanf %x 进
	//    signed int 会溢出归零——tablez 实测 0xc0/0xb0/0xa8 三槽全变 0（2026-10-25）。
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0
	}
	return int(v)
}

// ccLEBytes 小端整数 → sz 字节。
func ccLEBytes(v uint64, sz int) []byte {
	out := make([]byte, sz)
	for i := 0; i < sz; i++ {
		out[i] = byte(v >> (8 * uint(i)))
	}
	return out
}

// ── 栈上常量数组提取 ──

func ccStackConstArray(lines []string) []byte {
	slots := map[int][]byte{}
	lastMovabs := map[string][2]int{} // reg → {value, lineIdx}
	for idx, line := range lines {
		if m := ccMovabsRe.FindStringSubmatch(line); m != nil {
			lastMovabs[m[1]] = [2]int{ccHexInt(m[2]), idx}
			continue
		}
		if m := ccImmStoreRe.FindStringSubmatch(line); m != nil {
			sz := ccSize[m[1]]
			off := ccHexInt(m[2])
			v := ccHexInt(m[3]) & ((1 << (8 * sz)) - 1)
			slots[off] = ccLEBytes(uint64(v), sz)
			continue
		}
		if m := ccMovR2SRe.FindStringSubmatch(line); m != nil {
			mv, ok := lastMovabs[m[3]]
			if !ok {
				continue
			}
			// movabs 须紧邻（≤4 行）且中间无 call（防 strlen 返回值污染，tablez 实测）
			if idx-mv[1] > 4 {
				continue
			}
			called := false
			for k := mv[1] + 1; k < idx; k++ {
				if strings.Contains(lines[k], "call") {
					called = true
					break
				}
			}
			if called {
				continue
			}
			sz := ccSize[m[1]]
			off := ccHexInt(m[2])
			mask := uint64(1)<<(8*uint(sz)) - 1
			slots[off] = ccLEBytes(uint64(mv[0])&mask, sz)
		}
	}
	if len(slots) == 0 {
		return nil
	}
	offs := make([]int, 0, len(slots))
	for o := range slots {
		offs = append(offs, o)
	}
	// 降序排 + 取最长连续段（数组头在最大偏移；孤立槽如 canary 不并入）
	for i := 0; i < len(offs); i++ {
		for j := i + 1; j < len(offs); j++ {
			if offs[j] > offs[i] {
				offs[i], offs[j] = offs[j], offs[i]
			}
		}
	}
	best := []byte{}
	for i := 0; i < len(offs); {
		run := []byte{}
		expect := offs[i]
		j := i
		for j < len(offs) && offs[j] == expect {
			run = append(run, slots[offs[j]]...)
			expect -= len(slots[offs[j]])
			j++
		}
		// 前导零剥离后比较长度：孤立的 8 字节 0 槽（movabs 常量/对齐填充）会与真数组
		// 并成一段并遮蔽其头部（tablez 实测，本 objdump 版本槽位版图与 python 侧不同
		// ——剥离后按内容长度选段，两个 objdump 版本下都成立）。
		trimmed := bytes.TrimLeft(run, "\x00")
		if len(trimmed) > len(best) {
			best = trimmed
		}
		if j > i {
			i = j
		} else {
			i++
		}
	}
	return best
}

func ccXorKeys(lines []string) []int {
	var out []int
	seen := map[int]bool{}
	for _, line := range lines {
		var keys []int
		if m := ccXorImmRe.FindStringSubmatch(line); m != nil {
			keys = append(keys, ccHexInt(m[1])&0xFF)
		}
		if m := ccMovEsiRe.FindStringSubmatch(line); m != nil {
			keys = append(keys, ccHexInt(m[1])&0xFF)
		}
		for _, k := range keys {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}

func ccCmpFunction(asm string) *ccFunc {
	fns := ccSplitFunctions(asm)
	for i := range fns {
		if ccCmpCallRe.MatchString(strings.Join(fns[i].lines, "\n")) {
			return &fns[i]
		}
	}
	return nil
}

// ── 三检测器 ──

func ccCandidateXorConst(asm string) [][]byte {
	fn := ccCmpFunction(asm)
	if fn == nil {
		return nil
	}
	arr := bytes.TrimRight(ccStackConstArray(fn.lines), "\x00")
	if len(arr) < 6 {
		return nil
	}
	out := [][]byte{arr} // key=0 恒等
	for _, k := range ccXorKeys(strings.Split(asm, "\n")) {
		x := make([]byte, len(arr))
		for i, c := range arr {
			x[i] = c ^ byte(k)
		}
		out = append(out, x)
	}
	return out
}

func ccCandidateSubstTable(asm string, secs []ccSection, b []byte) [][]byte {
	fn := ccCmpFunction(asm)
	if fn == nil {
		return nil
	}
	arr := bytes.TrimRight(ccStackConstArray(fn.lines), "\x00")
	if len(arr) < 6 {
		return nil
	}
	var cands [][]byte
	// 替换表符号（trans_tbl）可能定义在别的函数 → 全文搜索
	for _, line := range strings.Split(asm, "\n") {
		m := ccLeaRipRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		sym := strings.ToLower(m[2])
		if !ccTblNameRe.MatchString(sym) {
			continue
		}
		va := uint64(0)
		fmt.Sscanf(m[1], "%x", &va)
		off, ok := ccV2O(secs, va)
		if !ok {
			continue
		}
		end := off + 1024
		if end > len(b) {
			end = len(b)
		}
		pairs := b[off:end]
		inv := map[byte]byte{}
		okCount := 0
		for i := 0; i+1 < len(pairs); i += 2 {
			frm, to := pairs[i], pairs[i+1]
			if frm == 0 && to == 0 {
				break
			}
			// 首次出现优先（tablez 实测：'u' 被后续伪映射覆写会污染真映射）
			if _, exists := inv[to]; !exists {
				inv[to] = frm
			}
			okCount++
		}
		if okCount < 8 {
			continue
		}
		cand := make([]byte, len(arr))
		for i, c := range arr {
			if v, exists := inv[c]; exists {
				cand[i] = v
			} else {
				cand[i] = '?'
			}
		}
		cands = append(cands, cand)
	}
	return cands
}

func ccCandidateTreeIndex(asm string, secs []ccSection, b []byte) [][]byte {
	addrByScale := map[int]uint64{}
	lines := strings.Split(asm, "\n")
	for idx, line := range lines {
		m := ccLeaScaleRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		scale := 0
		fmt.Sscanf(m[1], "%d", &scale)
		for j := idx; j < idx+4 && j < len(lines); j++ {
			if m2 := ccRipAddrRe.FindStringSubmatch(lines[j]); m2 != nil {
				va := uint64(0)
				fmt.Sscanf(m2[1], "%x", &va)
				addrByScale[scale] = va
				break
			}
		}
	}
	aAddr, okA := addrByScale[4]
	tAddr, okT := addrByScale[8]
	if !okA || !okT || tAddr <= aAddr {
		return nil
	}
	aOff, okA2 := ccV2O(secs, aAddr)
	tOff, okT2 := ccV2O(secs, tAddr)
	tEnd, okE := ccSecSpan(secs, tAddr)
	if !okA2 || !okT2 || !okE {
		return nil
	}
	nTarget := int((tEnd - tAddr) / 8)
	nArr := int((tAddr - aAddr) / 4)
	if nTarget < 1 || nTarget > 4096 || nArr < 1 || nArr > 65536 {
		return nil
	}
	arr := make([]int32, nArr)
	for i := 0; i < nArr; i++ {
		arr[i] = int32(binary.LittleEndian.Uint32(b[aOff+4*i:]))
	}
	tgt := make([]int64, nTarget)
	for i := 0; i < nTarget; i++ {
		tgt[i] = int64(binary.LittleEndian.Uint64(b[tOff+8*i:]))
	}
	for _, v := range tgt {
		if v < 0 || int(v) >= nArr {
			return nil
		}
	}
	out := make([]byte, 0, nTarget)
	for _, v := range tgt {
		out = append(out, byte(arr[v]&0xFF))
	}
	return [][]byte{out}
}

// ── 校验 / 求解入口 ──

func ccVerify(cand []byte, sha256Hex string) bool {
	if sha256Hex == "" {
		return ccFlagShapeRe.Match(cand)
	}
	sum := sha256.Sum256(cand)
	return hex.EncodeToString(sum[:]) == strings.ToLower(strings.TrimSpace(sha256Hex))
}

// ccSolve 对单个 ELF 附件跑三检测器；sha256Hex 非空时按真值选候选，
// 为空时按 flag 形态过滤（注册表路径）。无把握一律不返回。
func ccSolve(ctx context.Context, data []byte, sha256Hex string) []string {
	tmp, err := os.CreateTemp("", "secautomind-cc-*.bin")
	if err != nil {
		return nil
	}
	srcName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(srcName)
		return nil
	}
	tmp.Close()
	defer os.Remove(srcName)

	asm := objdumpDisasm(ctx, srcName)
	if asm == "" {
		return nil
	}
	secs := ccSections(srcName)
	var cands [][]byte
	if secs != nil {
		cands = append(cands, ccCandidateSubstTable(asm, secs, data)...)
		cands = append(cands, ccCandidateTreeIndex(asm, secs, data)...)
	}
	cands = append(cands, ccCandidateXorConst(asm)...)
	var out []string
	seen := map[string]bool{}
	for _, cand := range cands {
		if len(cand) == 0 || !ccVerify(cand, sha256Hex) {
			continue
		}
		s := string(cand)
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// tryConstCompare 注册表入口：对 ELF 形态附件跑常量比对求解（bin_const_compare）。
func tryConstCompare(ctx context.Context, text string, attachments map[string]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range attachments {
		if len(raw) < 64 || !bytes.HasPrefix([]byte(raw), []byte("\x7fELF")) {
			continue
		}
		for _, f := range ccSolve(ctx, []byte(raw), "") {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	return out
}
