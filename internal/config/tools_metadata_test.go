package config

import "testing"

// TestToolsMetadataConsistency 对受版本控制的 90 个工具配方做元数据一致性断言。
//
// 这里刻意不断言具体覆盖率数字（每次核实上游许可证都会变），
// 只断言不变量：已核实许可证的工具必须同时标注 source=upstream 与 upstream 仓库，
// 否则就会造出"有许可证却无来源"的死数据。
//
// ⚠️ 90 vs 对外口径 91 的差异是**既有设计**，不是笔误：
// `scripts/count_stats.py` 的 tools_yaml 把 tools/_shared_args.yaml（YAML anchor 锚点文件，
// 无 name/command）也计入（它同时排除 tools/risk_policy.yaml），故对外报 91；
// 本测试断言的是**真实可加载配方**数（= 92 个 yaml − risk_policy − _shared_args）。
// 变更史：2026-10-18 删 tools/lightx.yaml（对外 91->90，配方 90->89）；
//         2026-10-24 增 tools/bkcrack.yaml（对外 90->91，配方 89->90）。
// 下次增删 tools/*.yaml 时本数字与 AGENTS.md 第二条的分解式需同步更新。
func TestToolsMetadataConsistency(t *testing.T) {
	tools, err := LoadToolsFromDir("../../tools")
	if err != nil {
		t.Fatalf("LoadToolsFromDir: %v", err)
	}
	if len(tools) != 90 {
		t.Fatalf("工具配方数量应为 90，实际 %d（是否增删了 tools/*.yaml？改这里前先看本文件头部的口径说明）", len(tools))
	}

	var self, upstream, licKnown, licUnknown, hasUpstream int
	for i := range tools {
		tl := &tools[i]
		if tl.Name == "" {
			t.Errorf("tools[%d]: name 为空", i)
		}

		switch tl.Source {
		case "self":
			self++
		case "upstream":
			upstream++
		default:
			t.Errorf("%s: source=%q 应为 self 或 upstream", tl.Name, tl.Source)
		}

		// 不变量只朝一个方向：**已核实许可证 ⇒ 必须是 upstream 且有上游地址**。
		// 这是防"有许可证却无来源"的死数据（凭什么说自己是 MIT 却说不出是谁）。
		//
		// 刻意**不**做反向断言（"license 未核实 ⇒ upstream 必须为空"）：
		// 「上游已核实、许可证未核实」是正当状态，不是死数据。
		// 实例：gdb/objdump/strings 的上游（sourceware binutils-gdb）已从 GNU 官方页确认，
		// 但该包混合 GPLv2/GPLv3/LGPL 且两个官方镜像均被反爬拦截，逐文件许可未能核实。
		// 这种时候把"已确认的上游"也一并抹成空，等于扔掉已核实的证据。
		if tl.License == "" || tl.License == "unknown" {
			licUnknown++
		} else {
			licKnown++
			if tl.Source != "upstream" {
				t.Errorf("%s: license=%q 已核实，但 source=%q 不是 upstream", tl.Name, tl.License, tl.Source)
			}
			if tl.Upstream == "" {
				t.Errorf("%s: license=%q 已核实，但 upstream 为空", tl.Name, tl.License)
			}
		}
		// upstream 覆盖统计与 license 无关：上游可单独核实（见 binutils 三件套）
		if tl.Upstream != "" {
			hasUpstream++
		}
	}

	t.Logf("tools=%d self=%d upstream=%d license_known=%d license_unknown=%d upstream_known=%d",
		len(tools), self, upstream, licKnown, licUnknown, hasUpstream)
}
