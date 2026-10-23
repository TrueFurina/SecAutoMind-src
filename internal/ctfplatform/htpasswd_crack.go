package ctfplatform

// htpasswd_crack.go —— Apache .htpasswd 的 DES-crypt 离线破解。
//
// 背景：靶场链条是 LFI 读 /restricted/.htpasswd → 破解口令 → SSH 登录。
// 本机与服务器都没有 john/hashcat，因此用 des_crypt.go 的纯 Go 实现做字典攻击，
// 保持"离线可复现、零外部依赖"。
//
// 与 flag 判分无关：这是靶场演练能力，不产生 WebFinding。

import (
	"bufio"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
)

// HtpasswdEntry 是一条 "用户:哈希" 记录。
type HtpasswdEntry struct {
	User string
	Hash string
}

// CrackedCred 是破解成功的结果。
type CrackedCred struct {
	User     string
	Password string
	Hash     string
	Tries    int
}

// ParseHtpasswd 解析 .htpasswd 文本，只保留 DES-crypt（13 字符）条目。
// 其他算法（$apr1$/$2y$ 等）本实现不处理，直接跳过——宁可少报也不误报。
func ParseHtpasswd(text string) []HtpasswdEntry {
	var out []HtpasswdEntry
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 || i+1 >= len(line) {
			continue
		}
		user := strings.TrimSpace(line[:i])
		hash := strings.TrimSpace(line[i+1:])
		if len(hash) != 13 || strings.HasPrefix(hash, "$") {
			continue
		}
		out = append(out, HtpasswdEntry{User: user, Hash: hash})
	}
	return out
}

// crackOne 用 words 字典攻击单条记录，返回命中的口令（未命中返回空）。
// workers 个 goroutine 分片扫描，命中后通过原子标志提前退出。
func crackOne(e HtpasswdEntry, words []string, workers int) (string, int) {
	if workers < 1 {
		workers = 1
	}
	if workers > len(words) {
		workers = len(words)
	}
	if workers < 1 {
		return "", 0
	}
	salt := e.Hash[:2]

	var found atomic.Bool
	var mu sync.Mutex
	var hit string
	var tries int64
	var wg sync.WaitGroup

	chunk := (len(words) + workers - 1) / workers
	for w := 0; w < workers; w++ {
		lo := w * chunk
		hi := lo + chunk
		if hi > len(words) {
			hi = len(words)
		}
		if lo >= hi {
			continue
		}
		wg.Add(1)
		go func(seg []string) {
			defer wg.Done()
			n := 0
			for _, pw := range seg {
				if found.Load() {
					atomic.AddInt64(&tries, int64(n))
					return
				}
				n++
				if desCrypt(pw, salt) == e.Hash {
					if found.CompareAndSwap(false, true) {
						mu.Lock()
						hit = pw
						mu.Unlock()
					}
					atomic.AddInt64(&tries, int64(n))
					return
				}
			}
			atomic.AddInt64(&tries, int64(n))
		}(words[lo:hi])
	}
	wg.Wait()
	return hit, int(tries)
}

// CrackHtpasswd 对多条记录做字典攻击，返回全部命中结果。
func CrackHtpasswd(entries []HtpasswdEntry, words []string, workers int) []CrackedCred {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	var out []CrackedCred
	for _, e := range entries {
		if pw, tries := crackOne(e, words, workers); pw != "" {
			out = append(out, CrackedCred{User: e.User, Password: pw, Hash: e.Hash, Tries: tries})
		}
	}
	return out
}

// LoadWordlist 从文件读字典（每行一个口令，忽略空行与 # 注释）。
func LoadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var out []string
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// mangleSuffixes 是常见后缀（数字年份、符号、重复）。
var mangleSuffixes = []string{
	"", "1", "12", "123", "1234", "12345", "0", "01", "007", "!",
	"!!", "1!", "123!", "@123", "2020", "2021", "2022", "2023", "2024", "2025", "2026",
}

// leetMap 是常见 leet 替换。
var leetMap = map[rune]rune{'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}

// MangleWord 对单个词生成变形候选（保持与 john 常见规则一致的基本集合）。
// 目的不是穷举，而是把 10 万词的词典放大到百万级可试空间。
func MangleWord(w string) []string {
	if w == "" {
		return nil
	}
	lower := strings.ToLower(w)
	var forms []string
	forms = append(forms, lower)
	if len(lower) > 0 {
		forms = append(forms, strings.ToUpper(lower[:1])+lower[1:])
	}
	forms = append(forms, strings.ToUpper(lower))

	// leet 变形（仅全小写形式）
	var leet []rune
	for _, r := range lower {
		if m, ok := leetMap[r]; ok {
			leet = append(leet, m)
		} else {
			leet = append(leet, r)
		}
	}
	forms = append(forms, string(leet))

	seen := map[string]bool{}
	var out []string
	for _, f := range forms {
		for _, suf := range mangleSuffixes {
			c := f + suf
			if seen[c] {
				continue
			}
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// BuildCandidates 把词典展开成候选口令序列（mangle=true 时附加变形规则）。
func BuildCandidates(words []string, mangle bool) []string {
	if !mangle {
		return words
	}
	out := make([]string, 0, len(words)*40)
	for _, w := range words {
		out = append(out, MangleWord(w)...)
	}
	return out
}

// CrackHtpasswdBatched 按批展开词典做破解，避免一次性物化百万级候选导致内存爆掉。
// mangle=true 时每批词先变形；batchSize<=0 时默认 20000 词/批。
// 已破解的条目不再参与后续批次。
func CrackHtpasswdBatched(entries []HtpasswdEntry, words []string, mangle bool,
	batchSize, workers int) []CrackedCred {

	if batchSize <= 0 {
		batchSize = 20000
	}
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	remaining := append([]HtpasswdEntry{}, entries...)
	var out []CrackedCred

	for lo := 0; lo < len(words) && len(remaining) > 0; lo += batchSize {
		hi := lo + batchSize
		if hi > len(words) {
			hi = len(words)
		}
		cands := BuildCandidates(words[lo:hi], mangle)
		var next []HtpasswdEntry
		for _, e := range remaining {
			if pw, tries := crackOne(e, cands, workers); pw != "" {
				out = append(out, CrackedCred{User: e.User, Password: pw, Hash: e.Hash, Tries: tries})
			} else {
				next = append(next, e)
			}
		}
		remaining = next
	}
	return out
}

// BuiltinWordlist 是内置小字典：常见弱口令 + 靶场/CTF 常见取值 + 用户名派生。
// 用途是"离线可复现地验证破解链路"，不追求覆盖率；需要更强字典时用文件传入。
func BuiltinWordlist(users []string) []string {
	base := []string{
		"password", "Password", "password1", "passw0rd", "P@ssw0rd", "P@ssword",
		"123456", "12345678", "123456789", "12345", "1234", "111111", "000000",
		"admin", "Admin", "admin123", "administrator", "root", "toor", "test",
		"guest", "user", "login", "letmein", "welcome", "qwerty", "abc123",
		"iloveyou", "monkey", "dragon", "master", "sunshine", "princess",
		"lampsec", "LAMPSec", "lampsec123", "lamp", "ctf", "ctf4", "CTF4",
		"security", "hacker", "changeme", "secret", "default", "temp123",
		"system", "oracle", "mysql", "apache", "www", "web", "webmaster",
		"football", "baseball", "shadow", "superman", "trustno1", "starwars",
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, w := range base {
		add(w)
	}
	// 用户名派生：本身就是口令、首字母大写、加常见后缀
	for _, u := range users {
		lu := strings.ToLower(u)
		add(lu)
		if len(lu) > 0 {
			add(strings.ToUpper(lu[:1]) + lu[1:])
		}
		add(lu + "123")
		add(lu + "1")
		add(lu + "!")
	}
	return out
}
