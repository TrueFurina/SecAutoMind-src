# -*- coding: utf-8 -*-
"""CTF² 平台适配器（ctf2.dasctf.com——BUUCTF / DASCTF 迁移题库）

用法：
    export CTF2_AGENT_TOKEN="ctf2_..."        # 平台签发的 agent 令牌（69 字符，ctf2_ 前缀）
    export CTF2_BASE_URL="https://ctf2.dasctf.com"
    # 可选：export CTF2_PRACTICE="b9bbb32f-f186-458f-b90b-12440c0f6aea"   # BUUCTF 场（3244 题）

    from platform_ctf2 import fetch_challenges, fetch_challenge, download_attachment, submit_flag
    chs = fetch_challenges(PRACTICE, page=1)          # 题目列表
    detail = fetch_challenge(PRACTICE, chs[0]["id"])  # 题目详情
    download_attachment(detail["files"][0]["download_url"], "out.zip")  # 附件
    submit_flag(PRACTICE, chs[0]["id"], "flag{...}") # 提交（平台侧判分）

API 结构（2026-11-13 实测，agent 令牌）：
    GET  /api/open/v1/user/practice/                                    练习场列表
    GET  /api/open/v1/user/practice/{pgid}/challenges/?page=N&page_size=M
                                                                       题目列表（data.items / data.total / data.total_page）
    GET  /api/open/v1/user/practice/{pgid}/challenges/{cid}/           题目详情
                                                                       （data.description / data.files[].download_url
                                                                        / data.solved_sub_flag_count / data.total_sub_flag_count）
    POST /api/open/v1/user/practice/{pgid}/challenges/{cid}/submit/    body {"flag": "...", "confirmation": true}
                                                                       响应 data.accepted / data.is_solved
    认证：Authorization: Bearer <CTF2_AGENT_TOKEN>（**不是**用户 JWT）

2026-11-13 修正的三处（旧版本一直是 401 的根因）：
  1) 令牌变量名曾是 CTF2_TOKEN；平台实际下发的是 CTF2_AGENT_TOKEN。
     CTF2_TOKEN 在进程 / User / Machine 三级都不存在，所以旧代码永远读到空串。
  2) 前缀曾是 /api/v1；练习场的正确前缀是 /api/open/v1/user/practice/。
     /api/v1/... 对匿名和 agent 令牌一律 401（AUTH_REQUIRED）。
  3) 列表结果字段曾是 data.data；实际是 data.items（另附 total / total_page / page / page_size）。
     提交 body 还必须带 "confirmation": true，缺了会被判无效。

注意：文件名避免用 platform/（Python 标准库 module 名冲突）。
注意：本模块只跑「解题 + 提交」，不读平台侧答案。detail 里没有 flag 明文，
      只有 total_sub_flag_count（子 flag 个数）——判分真值永远在服务端。
"""
import json
import os
import urllib.error
import urllib.request

DEFAULT_BASE = "https://ctf2.dasctf.com"


def _base() -> str:
    return (os.environ.get("CTF2_BASE_URL") or DEFAULT_BASE).rstrip("/")


def _token() -> str:
    """取令牌：优先 CTF2_AGENT_TOKEN（平台实际下发名），回退 CTF2_TOKEN（旧名）。"""
    for name in ("CTF2_AGENT_TOKEN", "CTF2_TOKEN"):
        v = (os.environ.get(name) or "").strip()
        if v:
            return v
    return ""


def _api() -> str:
    return f"{_base()}/api/open/v1"


def _req(method: str, path: str, body: dict = None, timeout: int = 20) -> dict:
    """带认证调 CTF² API（返回解包后的 JSON）。

    网络层错误（4xx/5xx）不是异常而是有信息量的结果，故把 HTTPError 的 body 也解析出来。
    """
    url = f"{_api()}{path}"
    headers = {"Authorization": f"Bearer {_token()}", "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {"_http_status": e.code, "_body": raw}
        parsed.setdefault("_http_status", e.code)
        return parsed


def list_practices(timeout: int = 20) -> list:
    """列出当前令牌可见的练习场——[{id, name, challenge_count, end_time, ...}]。"""
    d = _req("GET", "/user/practice/", timeout=timeout)
    data = d.get("data") or {}
    return data.get("items") or []


def fetch_challenges(practice_id: str, page: int = 1, page_size: int = 20,
                     timeout: int = 20) -> list:
    """题目列表——返回 [{id, name, category, points, has_container, ...}]。

    实测列表在 data.items（不是 data.data / data.results）。
    """
    d = _req("GET", f"/user/practice/{practice_id}/challenges/"
                    f"?page={page}&page_size={page_size}", timeout=timeout)
    data = d.get("data") or {}
    return data.get("items") or []


def fetch_all_challenges(practice_id: str, page_size: int = 50,
                         max_pages: int = 200, timeout: int = 20) -> list:
    """翻页拉全某练习场的题目列表。

    2026-11-13 实测：服务端**忽略** page_size 参数，固定每页 50 条
    （传 page_size=5 仍返回 50 条）。所以不能用 len(items) < page_size 判翻页，
    必须读响应里的 data.total_page 作为终止条件，否则会提前截断。
    """
    out = []
    total_page = None
    for page in range(1, max_pages + 1):
        d = _req("GET", f"/user/practice/{practice_id}/challenges/"
                        f"?page={page}&page_size={page_size}", timeout=timeout)
        data = d.get("data") or {}
        items = data.get("items") or []
        if total_page is None:
            total_page = data.get("total_page")
        if not items:
            break
        out.extend(items)
        if total_page is not None and page >= int(total_page):
            break
    return out


def fetch_challenge(practice_id: str, challenge_id: str, timeout: int = 20) -> dict:
    """题目详情——{name, category, description, files, total_sub_flag_count, ...}。"""
    d = _req("GET", f"/user/practice/{practice_id}/challenges/{challenge_id}/",
             timeout=timeout)
    return d.get("data") or {}


def download_attachment(url: str, out_path: str, timeout: int = 60) -> str:
    """下载附件（ctf2-files.dasctf.com 直链）到本地。"""
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    with open(out_path, "wb") as f:
        f.write(data)
    return out_path


def submit_flag(practice_id: str, challenge_id: str, flag: str,
                confirmation: bool = True, timeout: int = 25) -> dict:
    """提交 flag——返回平台判分结果（data.accepted / data.is_solved）。

    实测 body 必须带 confirmation=true，否则平台判无效提交。
    """
    return _req("POST", f"/user/practice/{practice_id}/challenges/{challenge_id}/submit/",
                {"flag": flag, "confirmation": confirmation}, timeout=timeout)
