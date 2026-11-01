package pyskill

import (
	"fmt"
	"testing"
)

// L2 是确定性路由，猜不出 kind 这类语义分派参数。2026-11-01 实测：
// 只给 path 时 crypto_knapsack_mhk 2.4 秒返回 "unknown kind"，L2 等于没接上。
// 修法是用源码里的 `if kind == "mhk2_decrypt"` 分支当候选值逐个试。
// 这些用例锁住展开规则（顺序、边界、尊重显式值），避免以后改坏成"盲试两小时"。
func TestParamVariantsExpandsDispatch(t *testing.T) {
	r := &Runner{skillContracts: map[string]skillContract{
		"crypto_knapsack_mhk": {
			Params:   "ct,kind,path,pk",
			Dispatch: map[string][]string{"kind": {"mhk2_decrypt", "recover_key"}},
		},
	}}
	base := map[string]any{"path": "/tmp/output.txt"}
	got := r.paramVariants("crypto_knapsack_mhk", base)

	if len(got) != 3 {
		t.Fatalf("应展开成 1 基础 + 2 分派 = 3 个变体，实际 %d: %v", len(got), got)
	}
	// 第一个必须是基础参数（不改变"原样先试一次"的语义）。
	if _, has := got[0]["kind"]; has {
		t.Errorf("第一个变体不应带猜测的 kind: %v", got[0])
	}
	if got[1]["kind"] != "mhk2_decrypt" || got[2]["kind"] != "recover_key" {
		t.Errorf("分派顺序应严格按源码出现顺序：%v", got)
	}
	// 基础参数必须保留（否则 path 丢了，skill 找不到文件）。
	for i, v := range got {
		if v["path"] != "/tmp/output.txt" {
			t.Errorf("第 %d 个变体丢了 path: %v", i, v)
		}
	}
	// 不能污染调用方传入的 map。
	if _, has := base["kind"]; has {
		t.Error("paramVariants 改写了调用方的 base map")
	}
}

func TestParamVariantsRespectsExplicitValue(t *testing.T) {
	r := &Runner{skillContracts: map[string]skillContract{
		"crypto_knapsack_mhk": {Dispatch: map[string][]string{"kind": {"mhk2_decrypt"}}},
	}}
	got := r.paramVariants("crypto_knapsack_mhk", map[string]any{"kind": "recover_key"})
	if len(got) != 1 || got[0]["kind"] != "recover_key" {
		t.Fatalf("调用方已显式指定 kind 时不应再叠加猜测，实际: %v", got)
	}
}

func TestParamVariantsNoContractIsIdentity(t *testing.T) {
	r := &Runner{skillContracts: map[string]skillContract{
		"zip_chain_decode": {Params: "path,zip_path"},
	}}
	got := r.paramVariants("zip_chain_decode", map[string]any{"path": "/tmp/hard.zip"})
	if len(got) != 1 {
		t.Fatalf("无分派信息的 skill 应只返回基础参数，实际 %d 个: %v", len(got), got)
	}
}

// 上限：15 个 skill 用 kind 分派，若某个 skill 有 10 个分支就会把预算吃光。
func TestParamVariantsCapped(t *testing.T) {
	vals := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		vals = append(vals, fmt.Sprintf("k%d", i))
	}
	r := &Runner{skillContracts: map[string]skillContract{
		"x": {Dispatch: map[string][]string{"kind": vals}},
	}}
	if got := r.paramVariants("x", map[string]any{}); len(got) > maxDispatchVariants {
		t.Fatalf("展开数应被 %d 限制，实际 %d", maxDispatchVariants, len(got))
	}
}
