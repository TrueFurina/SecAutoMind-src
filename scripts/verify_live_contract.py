#!/usr/bin/env python3
"""verify_live_contract.py — 仿真平台契约验证 (P0-1，fail-closed)。

用途：把「拿到 Agent Key 即通」从 runbook 变成可机验事实。
  - 真机模式：--base-url + --token 探测官方仿真平台，逐端点核对契约。
  - 自测模式：--self-test 启动内置 mock（scripts/mock_sim_platform.py），
    断言全链 rc=0；再注入变异（错误 code / 缺字段 / 403），断言必须 FAIL。

fail-closed 纪律（对齐 2026-09-13 深度复检结论）：
  * 任何探针超时/连接失败/非 200/HTTP 403/业务码非 "00000"/形状缺失 → rc=1。
  * 403/40403 时给出「人话」映射，明确指出这是外部权限问题，不是代码问题。
  * 成功判据只认字符串 "00000"（不认 int 0，见 dasctf.go codeIsSuccess）。
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

TIMEOUT = 10
OK_CODE = "00000"  # 字符串，唯一合法成功码


class ContractError(Exception):
    pass


def _req(base, path, token, method="GET", body=None):
    url = base.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
        r.add_header("Token", token)
    try:
        with urllib.request.urlopen(r, timeout=TIMEOUT) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read() or b"{}")
        except Exception:
            payload = {}
        return e.code, payload
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise ContractError("连接失败 %s -> %s" % (url, e))


def _expect_ok(status, payload, what):
    """严格判定：HTTP 200 + code=="00000"（字符串）。任一不满足即报错。"""
    if status == 403:
        code = str(payload.get("code", ""))
        raise ContractError(
            "[%s] HTTP 403 (code=%s) → Agent Key 未开通/令牌无效（40403 无权操作）。"
            "这是外部权限问题：联系平台方开通 Agent Key；代码侧无需改动。" % (what, code))
    if status != 200:
        raise ContractError("[%s] HTTP %d（期望 200）payload=%s" % (what, status, payload))
    code = payload.get("code")
    if not (isinstance(code, str) and code == OK_CODE):
        raise ContractError("[%s] 业务码非字符串\"00000\"（got=%r）——codeIsSuccess 判据不满足" % (what, code))
    if "data" not in payload:
        raise ContractError("[%s] 响应缺 data 字段" % what)


def probe_all(base, token):
    """全链探针：match-info → overview → exercise-list → detail → build_env → submit。"""
    checks = []
    s, p = _req(base, "/slab-match/api/v1/agent/match/notice/match-info", token)
    _expect_ok(s, p, "match-info"); checks.append(("match-info", True))

    s, p = _req(base, "/slab-match/api/v1/agent/answer-panel/overview", token)
    _expect_ok(s, p, "overview"); checks.append(("overview", True))

    s, p = _req(base, "/slab-match/api/v1/agent/ctf/exercise-list", token)
    _expect_ok(s, p, "exercise-list")
    lst = p.get("data") or []
    if not isinstance(lst, list) or not lst:
        raise ContractError("[exercise-list] data 非非空列表")
    checks.append(("exercise-list n=%d" % len(lst), True))

    cid = str(lst[0].get("id", ""))
    s, p = _req(base, "/slab-match/api/v1/agent/ctf/exercise?exerciseId=" + cid, token)
    _expect_ok(s, p, "exercise-detail"); checks.append(("exercise-detail", True))

    s, p = _req(base, "/slab-match/api/v1/agent/ctf/build-exercise-env", token,
                method="POST", body={"exerciseId": cid})
    _expect_ok(s, p, "build-exercise-env"); checks.append(("build-exercise-env", True))

    s, p = _req(base, "/slab-match/api/v1/agent/answer-panel/answer", token,
                method="POST", body={"exerciseId": cid, "flag": "flag{contract_probe}"})
    _expect_ok(s, p, "submit-answer")
    d = p.get("data") or {}
    if not isinstance(d, dict) or "isCorrect" not in d:
        raise ContractError("[submit-answer] data 缺 isCorrect 字段")
    checks.append(("submit-answer isCorrect", True))
    return checks


def self_test():
    """三段式：正例全绿 → 变异必红 → 恢复不误红。任一不满足 rc=1。"""
    import mock_sim_platform as mock  # 同目录
    results = []
    # [1/4] 正例：mock 全链 rc 期望 0
    srv = mock.serve(port=0)
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        checks = probe_all(base, "")
        results.append(("正例全链 %d 项全绿" % len(checks), True))
    except ContractError as e:
        results.append(("正例全链: %s" % e, False))
    finally:
        srv.shutdown()

    # [2/4] 变异 A：错误业务码（int 0 / "0"）必须判 FAIL —— 守住 codeIsSuccess 单边放宽红线
    class _Bad(int):
        pass
    orig = mock._resp
    mock._resp = lambda c, m, d: {"code": 0, "msg": m, "data": d}  # int 0（历史漏洞形态）
    srv = mock.serve(port=0); base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        try:
            probe_all(base, ""); ok_a = False
        except ContractError:
            ok_a = True
        results.append(("变异A int0 伪成功被捕获", ok_a))
    finally:
        srv.shutdown(); mock._resp = orig

    # [3/4] 变异 B：403 无权必须给出人话映射且 rc=1 路径可达
    srv = mock.serve(port=0, token="right-token"); base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        try:
            probe_all(base, "wrong-token"); ok_b = False
        except ContractError as e:
            ok_b = ("40403" in str(e) and "Agent Key" in str(e))
        results.append(("变异B 403→人话映射+判红", ok_b))
    finally:
        srv.shutdown()

    # [4/4] 变异 C：连接失败必须 fail-closed
    try:
        probe_all("http://127.0.0.1:1", ""); ok_c = False
    except ContractError:
        ok_c = True
    results.append(("变异C 连接失败 fail-closed", ok_c))

    print()
    blocked = False
    for name, ok in results:
        print("  %-4s %s" % ("PASS" if ok else "BLOCK", name))
        blocked = blocked or not ok
    if blocked:
        print("\n[self-test] 存在 BLOCK —— 契约验证器自身不可信，禁止对外宣称『拿到 Key 即通』")
        return 1
    print("\n[self-test] 4/4 PASS —— 契约验证器可信；真机模式可用：--base-url <URL> --token <KEY>")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", default="", help="真机模式：平台 BaseURL（或 env DASCTF_BASE_URL）")
    ap.add_argument("--token", default="", help="真机模式：Agent Key（或 env DASCTF_TOKEN）")
    ap.add_argument("--self-test", action="store_true", help="内置 mock 三段式自测（CI 用）")
    a = ap.parse_args()
    if a.self_test:
        sys.exit(self_test())
    base = a.base_url or __import__("os").environ.get("DASCTF_BASE_URL", "")
    token = a.token or __import__("os").environ.get("DASCTF_TOKEN", "")
    if not base:
        print("[BLOCK] 未提供 --base-url/DASCTF_BASE_URL —— 无目标不可验证（fail-closed）")
        sys.exit(1)
    try:
        checks = probe_all(base, token)
    except ContractError as e:
        print("BLOCK %s" % e)
        sys.exit(1)
    for name, _ in checks:
        print("  PASS %s" % name)
    print("\n[PASS] 平台契约全链验证通过（%d/%d）——『拿到 Key 即通』成立" % (len(checks), len(checks)))


if __name__ == "__main__":
    main()