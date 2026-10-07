package ctfplatform

import (
	"context"
	"net/http/httptest"
	"testing"
)

// TestProductSolverSolvesUploadAndAPIRange 填补验证真空：
// 产品确定性求解器（非 TestLiveTargetEndToEnd 里写死的 probe 闭包）必须能端到端解穿
// 2009 上传绕过与 2013 API 未授权这两道此前"专用引擎从未被产品求解器验证过"的靶机。
// 这是 P0 修复（上传 .php/MIME 绕过 + 上传响应体抽 flag + API 内部头轮试）的回归门禁。
func TestProductSolverSolvesUploadAndAPIRange(t *testing.T) {
	t.Setenv("SECAUTOMIND_WEB_EXPLOIT", "1")

	// ---------- 2009 文件上传绕过 ----------
	// 靶机 targetUploadBypass 只认 Content-Type==image/png 或 Filename 以 .php 结尾。
	upSrv := httptest.NewServer(targetUploadBypass("flag{upload_bypass_ok}"))
	defer upSrv.Close()
	upDesc := "靶机地址 " + upSrv.URL + " 存在文件上传绕过漏洞，请拿下 flag。"
	got := uploadAttackFromText(context.Background(), upDesc)
	if len(got) == 0 {
		t.Fatalf("❌ 产品上传求解器未解出 2009 上传靶机 flag（P0 修复未生效）")
	}
	t.Logf("✅ 产品上传求解器命中 2009: %s", got[0])

	// ---------- 2013 API 未授权访问 ----------
	// 靶机 targetAPIAuthz 端点 /api/v1/admin/keys 需 X-Internal: 1 才返回 flag。
	apiSrv := httptest.NewServer(targetAPIAuthz("flag{api_authz_ok}"))
	defer apiSrv.Close()
	apiDesc := "靶机地址 " + apiSrv.URL + " 存在 API 未授权访问，请直接访问管理端点。"
	gotAPI := ExploitURLsInText(context.Background(), apiDesc)
	if len(gotAPI) == 0 {
		t.Fatalf("❌ 产品求解器未解出 2013 API 未授权靶机 flag（P0 修复未生效）")
	}
	t.Logf("✅ 产品求解器命中 2013: %s", gotAPI[0])
}

// TestProductSolverSolvesCmdInjectRange 填补验证真空：
// 产品确定性求解器（非 TestLiveTargetEndToEnd 写死的 probe 闭包）必须能端到端解穿
// 2008 命令注入靶机。这是 P1 修复（阶段 6 端点从写死 /cmd 改为 /cmd + /ping 轮试）的回归门禁。
// 靶机 targetCmdInject 只认 /ping 端点 + host 参数（参数值含 ;|&$` 即回显 flag）。
func TestProductSolverSolvesCmdInjectRange(t *testing.T) {
	t.Setenv("SECAUTOMIND_WEB_EXPLOIT", "1")

	cmdSrv := httptest.NewServer(targetCmdInject("flag{cmd_inject_ok}"))
	defer cmdSrv.Close()
	cmdDesc := "靶机地址 " + cmdSrv.URL + " 存在命令注入漏洞，请拿下 flag。"
	got := ExploitURLsInText(context.Background(), cmdDesc)
	if len(got) == 0 {
		t.Fatalf("❌ 产品求解器未解出 2008 命令注入靶机 flag（P1 修复未生效）")
	}
	t.Logf("✅ 产品求解器命中 2008: %s", got[0])
}

// TestProductSolverSolvesNoSQLRange 填补验证真空：
// 产品确定性求解器（非写死 probe）必须能端到端解穿 2012 NoSQL 注入靶机。
// 这是 2012 靶机诚实性 bug 修复（题面写"MongoDB 操作符绕过"，旧靶机只认顶层空键、还把
// 顶层 $ne 返 401，连人类按题面都构造不出）的回归门禁。靶机 targetNoSQLBypass 在 /login，
// 接受嵌套操作符 {"user":{"$ne":""}}（题面真实形态）或兼容顶层空键 {"":""}。
func TestProductSolverSolvesNoSQLRange(t *testing.T) {
	t.Setenv("SECAUTOMIND_WEB_EXPLOIT", "1")

	nosqlSrv := httptest.NewServer(targetNoSQLBypass("flag{nosql_ok}"))
	defer nosqlSrv.Close()
	nosqlDesc := "靶机地址 " + nosqlSrv.URL + " 存在 NoSQL 注入绕过登录，请拿下 flag。"
	got := ExploitURLsInText(context.Background(), nosqlDesc)
	if len(got) == 0 {
		t.Fatalf("❌ 产品求解器未解出 2012 NoSQL 靶机 flag（诚实性 bug 修复未生效）")
	}
	t.Logf("✅ 产品求解器命中 2012: %s", got[0])
}
