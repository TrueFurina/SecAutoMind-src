package ctfplatform

import (
	"testing"
)

// BenchmarkDESCrypt 测单条 crypt 计算耗时（破解速率 = 1/单条耗时）。
func BenchmarkDESCrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		desCrypt("password", "ab")
	}
}

// BenchmarkCrackOne 测单条哈希的字典扫描吞吐（含分片并发）。
func BenchmarkCrackOne(b *testing.B) {
	words := BuiltinWordlist([]string{"ghighland", "pmoore"})
	entry := HtpasswdEntry{User: "ghighland", Hash: desCrypt("not-in-list-zzz", "8R")}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crackOne(entry, words, 8)
	}
}
