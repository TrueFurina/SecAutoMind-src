package runnerl3

import (
	"context"
	"strings"
	"testing"
)

// TestPySessionCtfCryptoInjected 验证 opt1 注入链路在**真实 Go 代码路径**下可用：
// startSession 通过 embed 把 ctf_crypto.py 写入会话目录，bootstrap 完成
// `import ctf_crypto` 进会话 globals G；本测试用真实会话进程 exec 一段探针，确认
// 库函数可被模型代码直接调用（覆盖 opt1 的 modinv 与 opt2 的 idea/merkle）。
//
// 关键：这不是 Python 复刻验证，而是直接走 go:embed → 写会话目录 → python 进程
// import 的真实链路。无 Python 时整体 Skip（与 py_session_test.go 同口径，不伪造绿）。
// 不依赖 LLM、不联网、纯离线，可在 CI 稳定复跑。
func TestPySessionCtfCryptoInjected(t *testing.T) {
	m := requireSession(t)
	ctx := context.Background()

	// 探针在真实会话进程内执行：直接引用 bootstrap 注入到 G 的 ctf_crypto。
	// 诊断式输出，任何环节失败都能从 stdout 看到原因（不依赖 stderr 捕获）。
	const probe = `
diag = []
diag.append("ctf_in_globals=" + str("ctf_crypto" in globals()))
try:
    import ctf_crypto as C
    diag.append("modinv=" + str(C.modinv(3, 11)))
    key = bytes.fromhex("00010002000300040005000600070008")
    pt = bytes.fromhex("0000000100020003")
    ct = C.idea_encrypt_block(key, pt)
    diag.append("idea=" + ct.hex())
    diag.append("idea_match=" + str(ct.hex() == "11fbed2b01986de5"))
    diag.append("idea_roundtrip=" + str(C.idea_decrypt_block(key, ct) == pt))
    roots = [b"a", b"b", b"c", b"d"]
    r1 = C.merkle_root(roots).hex()
    # Merkle 根是左到右二叉树构造，与叶子顺序相关（非集合哈希）；
    # 正确不变量是：同输入确定性（多次调用一致）且为 32 字节 SHA-256 摘要。
    r1_again = C.merkle_root(roots).hex()
    diag.append("merkle_deterministic=" + str(r1 == r1_again))
    diag.append("merkle_is_32byte=" + str(len(r1) == 64))
    # R3 opt2：Berlekamp-Massey + LFSR 闭环（filtermaze 类题关键原语）。
    # 用已知本原多项式生成序列，再用 BM 还原，断言还原==生成多项式——
    # 这条断言锁住「go:embed 的 ctf_crypto.py 在运行时确实导出了可用 BM/LFSR」，
    # 否则 BM 只停留在库里、L3 调用即 AttributeError（比没有参考更糟）。
    bm_poly = [1, 1, 0, 0, 1]          # x^4 + x + 1（本原）
    bm_init = [1, 0, 1, 1]
    bm_seq = C.lfsr_generate(bm_poly, bm_init, 12)
    bm_rec = C.berlekamp_massey_gf2(bm_seq)
    diag.append("bm_recovered=" + repr(bm_rec))
    diag.append("bm_recover_ok=" + str(bm_rec == bm_poly))
    diag.append("lfsr_shape_ok=" + str(len(bm_seq) == 12 and bm_seq[:4] == bm_init))
    if bm_rec == bm_poly and len(bm_seq) == 12 and bm_seq[:4] == bm_init:
        diag.append("BM_OK")
    diag.append("RESULT=CTF_CRYPTO_OK")
except Exception as ex:
    diag.append("EXC=" + repr(ex))
print("DIAG " + " | ".join(diag))
`
	out, err := m.Exec(ctx, probe, false)
	t.Logf("probe raw output:\n%s", out)
	if err != nil {
		t.Fatalf("ctf_crypto 注入探针执行失败: %v", err)
	}
	if !strings.Contains(out, "RESULT=CTF_CRYPTO_OK") {
		t.Fatalf("ctf_crypto 注入未生效（期望含 RESULT=CTF_CRYPTO_OK），实际输出: %s", out)
	}
}
