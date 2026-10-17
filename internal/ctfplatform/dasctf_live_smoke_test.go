package ctfplatform

// ───────────────────────── 真机冒烟 + 字段名校准 harness（决赛前持凭证即跑）─────────────────────────
//
// 设计原则（对齐本仓纪律「外部依赖无凭证即不伪造」）：
//   - 仅当 DASCTF_BASE_URL 与 DASCTF_TOKEN 同时设置时才运行，否则 t.Skip（CI 永绿）。
//   - 不伪造绿：真机字段命名未知，本 harness 只做「连通性 + 协议 + 字段导出校准」，
//     把原始 challenge_detail 与 extractAttachmentURLs / extractAccess 的提取结果打印出来，
//     供决赛前人工或脚本比对——若真机字段命名与推断不同，据此微调 extractAttachmentURLs。
//   - 对未知真机形态只告警、不硬失败，避免把「真机未联调」误判成代码缺陷。

import (
	"context"
	"net/http"
	"os"
	"testing"

	"go.uber.org/zap"
)

// TestDasCTFLiveSmoke 真机冒烟：列表 → 选样本 → 建靶机/取地址/下载附件 → 导出原始详情做字段校准。
//
// 运行方式（决赛前）：
//
//	DASCTF_BASE_URL=https://<平台> DASCTF_TOKEN=<token> go test ./internal/ctfplatform/ -run TestDasCTFLiveSmoke -v
func TestDasCTFLiveSmoke(t *testing.T) {
	baseURL := os.Getenv("DASCTF_BASE_URL")
	token := os.Getenv("DASCTF_TOKEN")
	if baseURL == "" || token == "" {
		t.Skip("跳过真机冒烟：未设置 DASCTF_BASE_URL / DASCTF_TOKEN（按纪律不伪造绿）")
	}

	p := NewDasCTFPlatform(baseURL, token, zap.NewNop())
	p.MaxRetries = 2
	p.RetryBackoff = 2 * 1000 * 1000 * 1000 // 2s
	ctx := context.Background()

	list, err := p.ListChallenges(ctx)
	if err != nil {
		// 平台/网络/凭证环境问题属于环境态，不把环境故障当代码缺陷硬红 CI；
		// 协议正确性已由 TestRealClient* 在 httptest 下锁死。明确跳过并留痕。
		t.Skipf("⚠️ 真机 ListChallenges 失败（平台/网络/凭证环境态，跳过校准）: %v", err)
	}
	t.Logf("✅ 真机连通；题目数=%d", len(list))

	// 选一道有实例或附件的题做校准样本；都没有则取首题
	var sample *Challenge
	for i := range list {
		if list[i].HasInstance || list[i].HasAttachment {
			sample = &list[i]
			break
		}
	}
	if sample == nil && len(list) > 0 {
		sample = &list[0]
	}
	if sample == nil {
		t.Skip("真机无题目，跳过样本校准")
	}
	t.Logf("🎯 校准样本题号=%s  hasInstance=%v  hasAttachment=%v", sample.ID, sample.HasInstance, sample.HasAttachment)

	if sample.HasInstance {
		inst, ierr := p.CreateInstance(ctx, sample.ID)
		if ierr != nil {
			t.Logf("⚠️ CreateInstance 真机返回错误（决赛前需核实端点/权限）: %v", ierr)
		} else {
			t.Logf("✅ CreateInstance -> instance_id=%q status=%q", inst.InstanceID, inst.Status)
			acc, aerr := p.GetAccess(ctx, inst.InstanceID)
			if aerr != nil {
				t.Logf("⚠️ GetAccess 真机返回错误（靶机地址字段可能需校准）: %v", aerr)
			} else {
				t.Logf("✅ GetAccess -> host=%s port=%d url=%s", acc.Host, acc.Port, acc.URL)
			}
		}
	}

	// 字段名校准：拉回题目详情，检查附件 URL / 靶机地址是否被正确提取
	ch, gerr := p.GetChallenge(ctx, sample.ID)
	if gerr != nil {
		t.Logf("⚠️ GetChallenge 真机返回错误: %v", gerr)
	} else {
		t.Logf("📎 GetChallenge -> hasInstance=%v hasAttachment=%v attachmentURLs=%v",
			ch.HasInstance, ch.HasAttachment, ch.AttachmentURLs)
		if ch.HasAttachment && len(ch.AttachmentURLs) == 0 {
			t.Logf("🔴 校准告警：题 %s 标记为有附件但 extractAttachmentURLs 未提取到 URL（字段名可能需按真机调整）", sample.ID)
		}
	}

	// 导出原始 challenge_detail，供人工/脚本校准字段命名
	raw, _, rerr := p.doRequestURL(ctx, http.MethodGet,
		p.Endpoints["challenge_detail"]+"?exerciseId="+sample.ID, nil)
	if rerr == nil {
		t.Logf("📄 RAW challenge_detail(%s):\n%s", sample.ID, string(raw))
	} else {
		t.Logf("⚠️ 拉取 RAW challenge_detail 失败: %v", rerr)
	}
}
