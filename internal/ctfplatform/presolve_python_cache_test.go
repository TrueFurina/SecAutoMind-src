package ctfplatform

// Python 兜底缓存的并发与边界用例。
//
// 为什么单独测缓存：`tryPythonLegacyFallback` 是**并发入口**（Presolve 多题并行），
// 而缓存是它唯一的有共享可变状态的部分。历史上这里踩过一次真坑——首版用包级变量
// `pyFallbackRan` 传"是否真跑完"，并发下即数据竞争；已改为返回值。
// 本文件把缓存抽出的读写入口（pyCacheGet/pyCachePut）直接打，-race 下可验证。

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
)

// TestPyFallbackCacheConcurrent 32 goroutine × 300 次读写，键空间只有 8 个
// ——刻意制造"同键并发读写"，这是缓存最容易出竞争/撕裂的形态。
func TestPyFallbackCacheConcurrent(t *testing.T) {
	pyCacheReset()
	t.Cleanup(pyCacheReset)

	const (
		goroutines = 32
		iters      = 300
		keySpace   = 8
	)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				n := i % keySpace
				key := sha256.Sum256([]byte(fmt.Sprintf("q-%d", n)))
				want := fmt.Sprintf("flag{%d}", n)
				if got, ok := pyCacheGet(key); ok {
					// 同键的值必须确定：读到别的键的值 = 索引/写回错乱
					if len(got) != 1 || got[0] != want {
						t.Errorf("键 q-%d 读到错误值 %v（期望 [%s]）", n, got, want)
						return
					}
					continue
				}
				pyCachePut(key, []string{want})
			}
		}()
	}
	wg.Wait()

	// 收敛后：8 个键都应命中且值正确
	for n := 0; n < keySpace; n++ {
		key := sha256.Sum256([]byte(fmt.Sprintf("q-%d", n)))
		got, ok := pyCacheGet(key)
		if !ok || len(got) != 1 || got[0] != fmt.Sprintf("flag{%d}", n) {
			t.Fatalf("键 q-%d 最终状态错误：ok=%v got=%v", n, ok, got)
		}
	}
}

// TestPyFallbackCacheNegativeResult 负结果（nil）必须能与"未缓存"区分开。
// 这是缓存正确性的关键：runner.py 对同一输入确定性，所以"没解出"值得缓存；
// 但若把 nil 和 miss 混为一谈，就会每轮重新跑一遍 9.7s 的子进程。
func TestPyFallbackCacheNegativeResult(t *testing.T) {
	pyCacheReset()
	t.Cleanup(pyCacheReset)

	key := sha256.Sum256([]byte("no-solution-input"))
	if _, ok := pyCacheGet(key); ok {
		t.Fatal("前置：空缓存不该命中")
	}
	pyCachePut(key, nil)
	got, ok := pyCacheGet(key)
	if !ok {
		t.Fatal("负结果未被缓存——会把\"没解出\"当成 miss，每轮重跑 9.7s 子进程")
	}
	if len(got) != 0 {
		t.Fatalf("负结果应为空切片，得到 %v", got)
	}
}

// TestPyFallbackCacheBound 上界：超过 pyFallbackCacheMax 后整体清空，size 不越界。
func TestPyFallbackCacheBound(t *testing.T) {
	pyCacheReset()
	t.Cleanup(pyCacheReset)

	for i := 0; i < pyFallbackCacheMax+50; i++ {
		key := sha256.Sum256([]byte(fmt.Sprintf("bound-%d", i)))
		pyCachePut(key, []string{fmt.Sprintf("flag{%d}", i)})
	}
	pyFallbackMu.Lock()
	size := len(pyFallbackCache)
	pyFallbackMu.Unlock()
	if size > pyFallbackCacheMax {
		t.Fatalf("缓存超界：%d > %d（上界保护失效，长赛程会无限增长）", size, pyFallbackCacheMax)
	}
	if size == 0 {
		t.Fatal("清空后应立即开始重新累积，不该是 0（说明清空后没再写入）")
	}
}
