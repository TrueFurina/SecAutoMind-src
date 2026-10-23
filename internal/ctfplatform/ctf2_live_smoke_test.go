package ctfplatform

// CTF² 真机冒烟 + 字段校准 harness。
//
// 运行方式（1024 快闪赛赛前调试）：
//
//	CTF2_BASE_URL=https://ctf2.dasctf.com CTF2_AGENT_TOKEN=<token> go test ./internal/ctfplatform/ -run TestCTF2LiveSmoke -v
//
// 设计原则（对齐 dasctf_live_smoke_test.go）：
//   - 仅当 CTF2_BASE_URL 与 CTF2_AGENT_TOKEN 同时设置时才运行，否则 t.Skip（CI 永绿）。
//   - 不伪造绿：真机行为未知时只做「连通性 + 上下文发现 + 字段提取」校准，输出 RAW 供比对。
//   - 只做只读 + 开环境（调试赛允许）；不提交 flag（避免误交占尝试/触发风控）。

import (
	"context"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestCTF2LiveSmoke(t *testing.T) {
	baseURL := os.Getenv("CTF2_BASE_URL")
	token := os.Getenv("CTF2_AGENT_TOKEN")
	if baseURL == "" || token == "" {
		t.Skip("跳过 CTF² 真机冒烟：未设置 CTF2_BASE_URL / CTF2_AGENT_TOKEN（按纪律不伪造绿）")
	}

	p := NewCTF2Platform(baseURL, token, zap.NewNop())
	p.MaxRetries = 2
	p.RetryBackoff = 2 * 1000 * 1000 * 1000 // 2s
	ctx := context.Background()

	list, err := p.ListChallenges(ctx)
	if err != nil {
		t.Skipf("⚠️ CTF² 真机 ListChallenges 失败（平台/网络/凭证环境态，跳过校准）: %v", err)
	}
	t.Logf("✅ CTF² 真机连通；上下文 competition=%s stage=%s 题目数=%d",
		p.CompetitionID, p.StageID, len(list))

	if len(list) == 0 {
		t.Skip("CTF² 真机无题目，跳过样本校准")
	}
	for i, ch := range list {
		t.Logf("📋 [%d] %s | %s | %s | %d分 | instance=%v attach=%v solved=%v",
			i, ch.ID, ch.Title, ch.Category, ch.Score, ch.HasInstance, ch.HasAttachment, ch.Extra["is_solved"])
	}

	// 样本：优先带附件或靶机的题
	var sample *Challenge
	for i := range list {
		if list[i].HasAttachment || list[i].HasInstance {
			sample = &list[i]
			break
		}
	}
	if sample == nil {
		sample = &list[0]
	}
	t.Logf("🎯 校准样本: %s (%s)", sample.ID, sample.Title)

	// 详情校准
	ch, gerr := p.GetChallenge(ctx, sample.ID)
	if gerr != nil {
		t.Logf("⚠️ GetChallenge 真机返回错误: %v", gerr)
	} else {
		t.Logf("📄 GetChallenge -> desc_len=%d hasInstance=%v hasAttachment=%v flagFormat=%q submission_type=%v",
			len(ch.Description), ch.HasInstance, ch.HasAttachment, ch.FlagFormat, ch.Extra["submission_type"])
		files, _ := ch.Extra["files"].([]map[string]interface{})
		for _, f := range files {
			t.Logf("   📎 file_id=%v file_name=%v kind=%v", f["file_id"], f["file_name"], f["kind"])
		}
	}

	// 附件下载链（调试赛专属附件需先参赛生成，失败仅告警）
	if sample.HasAttachment {
		paths, derr := p.DownloadAttachment(ctx, sample.ID)
		if derr != nil {
			t.Logf("⚠️ DownloadAttachment 返回错误: %v", derr)
		} else {
			t.Logf("📥 DownloadAttachment -> %d 个附件: %v", len(paths), paths)
		}
	}

	// 靶机链（调试赛允许开环境）
	if sample.HasInstance {
		inst, ierr := p.CreateInstance(ctx, sample.ID)
		if ierr != nil {
			t.Logf("⚠️ CreateInstance 返回错误: %v", ierr)
		} else {
			t.Logf("🚀 CreateInstance -> instance_id=%q status=%q", inst.InstanceID, inst.Status)
			acc, aerr := p.GetAccess(ctx, sample.ID)
			if aerr != nil {
				t.Logf("⚠️ GetAccess 返回错误（环境可能仍 starting）: %v", aerr)
			} else {
				t.Logf("✅ GetAccess -> host=%s port=%d url=%s entries=%d",
					acc.Host, acc.Port, acc.URL, len(acc.EntryPoints))
			}
			derr := p.DestroyInstance(ctx, sample.ID)
			if derr != nil {
				t.Logf("⚠️ DestroyInstance 返回错误: %v", derr)
			} else {
				t.Logf("♻️ DestroyInstance OK")
			}
		}
	}

	// 比赛信息与排行榜（只读）
	mi, merr := p.GetMatchInfo(ctx)
	if merr != nil {
		t.Logf("⚠️ GetMatchInfo 返回错误: %v", merr)
	} else {
		t.Logf("🏆 GetMatchInfo -> name=%v status=%v", mi["name"], mi["status"])
	}
	ov, oerr := p.GetOverview(ctx)
	if oerr != nil {
		t.Logf("⚠️ GetOverview 返回错误: %v", oerr)
	} else {
		t.Logf("🏅 GetOverview -> board_state=%v items=%v", ov["board_state"], ov["total"])
	}
}

// TestCTF2LiveTargetChain CTF² 靶机链专项：对 has_container 的题完整跑
// CreateInstance → GetAccess → DestroyInstance（调试赛允许；正式赛勿在赛前乱开）。
func TestCTF2LiveTargetChain(t *testing.T) {
	baseURL := os.Getenv("CTF2_BASE_URL")
	token := os.Getenv("CTF2_AGENT_TOKEN")
	if baseURL == "" || token == "" {
		t.Skip("跳过 CTF² 靶机链：未设置 CTF2_BASE_URL / CTF2_AGENT_TOKEN")
	}

	p := NewCTF2Platform(baseURL, token, zap.NewNop())
	p.MaxRetries = 2
	p.RetryBackoff = 2 * 1000 * 1000 * 1000
	ctx := context.Background()

	list, err := p.ListChallenges(ctx)
	if err != nil {
		t.Skipf("⚠️ CTF² ListChallenges 失败: %v", err)
	}
	var target *Challenge
	for i := range list {
		if list[i].HasInstance {
			target = &list[i]
			break
		}
	}
	if target == nil {
		t.Skip("CTF² 无靶机题，跳过靶机链验证")
	}
	t.Logf("🎯 靶机样本: %s (%s)", target.ID, target.Title)

	inst, ierr := p.CreateInstance(ctx, target.ID)
	if ierr != nil {
		t.Fatalf("CreateInstance 失败: %v", ierr)
	}
	t.Logf("🚀 CreateInstance -> %s (%s)", inst.InstanceID, inst.Status)

	// 轮询 GetAccess 直到 access_ready
	ready := false
	var acc *Access
	for i := 0; i < 12; i++ {
		a, aerr := p.GetAccess(ctx, target.ID)
		if aerr != nil {
			t.Logf("  GetAccess#%d err: %v", i, aerr)
		} else {
			acc = a
			if r, _ := acc.Extra["access_ready"].(bool); r {
				ready = true
				break
			}
			t.Logf("  GetAccess#%d status=%v not ready", i, acc.Extra["status"])
		}
		time.Sleep(5 * time.Second)
	}
	if !ready || acc == nil {
		t.Fatalf("环境未就绪（12 次轮询未 access_ready）")
	}
	t.Logf("✅ GetAccess -> host=%s port=%d url=%s entries=%d remaining=%v",
		acc.Host, acc.Port, acc.URL, len(acc.EntryPoints), acc.Extra["remaining_seconds"])

	derr := p.DestroyInstance(ctx, target.ID)
	if derr != nil {
		t.Fatalf("DestroyInstance 失败: %v", derr)
	}
	t.Logf("♻️ DestroyInstance OK")
}
