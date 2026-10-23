package ctfplatform

// bkcrack_adapter_test.go —— 外调适配器的确定性测试（不依赖真实 bkcrack 二进制）。
//
// 覆盖点：
//  1. 二进制缺失 → ErrBkcrackUnavailable（fail-closed，不得静默当"解不出"）；
//  2. 正常输出 → 解析出 3 组 8 位十六进制密钥；
//  3. 输出缺 Keys 行 → 解析错误（不猜、不返回空密钥）；
//  4. 命令失败 → 错误带输出尾部（可诊断）；
//  5. 参数校验：空明文 / 负偏移 / 非法密钥格式。

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubBkcrack 用固定输出替换真实执行器，返回一个恢复函数。
func stubBkcrack(t *testing.T, out string, runErr error) {
	t.Helper()
	orig := bkcrackRunner
	bkcrackRunner = func(ctx context.Context, name string, args ...string) (string, error) {
		return out, runErr
	}
	t.Cleanup(func() { bkcrackRunner = orig })
}

// useFakeBkcrackBinary 造一个存在的假二进制，绕过 LookPath 探测。
func useFakeBkcrackBinary(t *testing.T) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bkcrack")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("造假的 bkcrack 失败: %v", err)
	}
	t.Setenv("SECAUTOMIND_BKCRACK", p)
}

func TestBkcrackUnavailableFailClosed(t *testing.T) {
	t.Setenv("SECAUTOMIND_BKCRACK", filepath.Join(t.TempDir(), "not-exist-bkcrack"))
	_, err := BkcrackRecoverKeys(context.Background(), "x.zip", "flag.txt", []byte("BOMCTF{"), 0)
	if !errors.Is(err, ErrBkcrackUnavailable) {
		t.Fatalf("二进制缺失必须返回 ErrBkcrackUnavailable，得到 %v", err)
	}
}

func TestBkcrackRecoverKeysParsesKeys(t *testing.T) {
	useFakeBkcrackBinary(t)
	stubBkcrack(t, "bkcrack 1.5.0\n[00:00:03] Keys: 7D1E8F2A 3B4C5D6E 9F0A1B2C\n", nil)
	keys, err := BkcrackRecoverKeys(context.Background(), "in.zip", "flag.txt", []byte("BOMCTF{"), 0)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if keys != "7d1e8f2a 3b4c5d6e 9f0a1b2c" {
		t.Fatalf("密钥应小写归一，得到 %q", keys)
	}
}

func TestBkcrackRecoverKeysWithoutKeysLineFailsClosed(t *testing.T) {
	useFakeBkcrackBinary(t)
	stubBkcrack(t, "[00:00:10] Z reduction using 5 bytes of known plaintext\n[00:00:10] No solution found\n", nil)
	_, err := BkcrackRecoverKeys(context.Background(), "in.zip", "flag.txt", []byte("BOMCTF{"), 0)
	if err == nil || !strings.Contains(err.Error(), "未找到 Keys") {
		t.Fatalf("缺 Keys 行必须报解析错误，得到 %v", err)
	}
}

func TestBkcrackRecoverKeysCommandFailureIncludesTail(t *testing.T) {
	useFakeBkcrackBinary(t)
	stubBkcrack(t, "error: cipher file not found\n", errors.New("exit status 1"))
	_, err := BkcrackRecoverKeys(context.Background(), "missing.zip", "flag.txt", []byte("BOMCTF{"), 0)
	if err == nil || !strings.Contains(err.Error(), "cipher file not found") {
		t.Fatalf("命令失败应带输出尾部，得到 %v", err)
	}
}

func TestBkcrackRecoverKeysParameterValidation(t *testing.T) {
	useFakeBkcrackBinary(t)
	if _, err := BkcrackRecoverKeys(context.Background(), "in.zip", "f", nil, 0); err == nil {
		t.Fatal("空明文必须拒绝")
	}
	if _, err := BkcrackRecoverKeys(context.Background(), "in.zip", "f", []byte("x"), -1); err == nil {
		t.Fatal("负偏移必须拒绝")
	}
}

func TestBkcrackDecryptEntryRejectsBadKeys(t *testing.T) {
	useFakeBkcrackBinary(t)
	for _, bad := range []string{"", "abcd", "zzzzzzzz 11111111 22222222", "12345678 12345678"} {
		if err := BkcrackDecryptEntry(context.Background(), "in.zip", "f", bad, "out.bin"); err == nil {
			t.Fatalf("非法密钥 %q 必须拒绝", bad)
		}
	}
}
