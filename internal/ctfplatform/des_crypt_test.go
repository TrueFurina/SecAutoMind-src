package ctfplatform

import "testing"

// 向量来源：Linux crypt(3)（经 python3.12 crypt 模块实测生成，2026-10-21）。
// 这是纯 Go 实现唯一可信的校准依据——DES 表错一位，13 字符输出就全错。
var desCryptVectors = []struct {
	password string
	salt     string
	want     string
}{
	{"password", "ab", "abJnggxhB/yWI"},
	{"password", "zz", "zzXUHfURnGg8I"},
	{"lampsec", "aa", "aaR//UA5F6x.c"},
	{"", "aa", "aaQSqAReePlq6"},
	{"a", "bb", "bbjRkx/QQC3mQ"},
	{"123456", "cc", "ccyi0i8sO5S1s"},
	{"admin", "dd", "ddWrItGUQVSfQ"},
	{"P@ssw0rd", "ee", "eeKskyrKFB0ko"},
	{"x", "//", "//skpRlKK259I"},
	{"longpassword123", "ff", "ffXz21g8.vNrU"},
}

func TestDESCryptVectors(t *testing.T) {
	for _, v := range desCryptVectors {
		got := desCrypt(v.password, v.salt)
		if got != v.want {
			t.Errorf("desCrypt(%q,%q) = %q, want %q", v.password, v.salt, got, v.want)
		}
	}
}

func TestDESCryptTruncatesToEightChars(t *testing.T) {
	// crypt(3) 只用口令前 8 字符
	a := desCrypt("12345678AAAA", "cc")
	b := desCrypt("12345678BBBB", "cc")
	if a != b {
		t.Errorf("前 8 字符相同应得到同一哈希: %q vs %q", a, b)
	}
	if a != desCrypt("12345678", "cc") {
		t.Errorf("应与 8 字符口令一致: %q", a)
	}
}

func TestDESCryptSaltAffectsOutput(t *testing.T) {
	// 同一口令不同盐必须不同（否则盐没生效）
	if desCrypt("password", "ab") == desCrypt("password", "zz") {
		t.Fatal("不同盐产生了相同哈希，盐未生效")
	}
}
