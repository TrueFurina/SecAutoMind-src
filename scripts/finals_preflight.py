#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""决赛赛前预检（go / no-go 结论）。

为什么需要：本轮冲刺发现的三处生产缺口（起靶机 / 附件 / 题干补全）都靠**配置开关**打开，
而开关默认关闭。赛时一忙漏设，能力就又回到"休眠"状态 —— 组件单测全绿也照样 0 分。
本脚本把"开没开、链通不通、门禁绿不绿"一次跑完并给出结论，避免靠人肉核对 runbook。

用法：
  python scripts/finals_preflight.py            # 快速预检（演练 + 门禁 + 开关检查，约 1 分钟）
  python scripts/finals_preflight.py --full     # 追加整包 go test（数分钟）
  python scripts/finals_preflight.py --json     # 机器可读输出（供 CI/复盘）
  python scripts/finals_preflight.py --phase pre   # 赛前模式：当天才开的开关只提示不阻塞

两个阶段（09-24/10-05 补）：
  `--phase final`（**默认**，保持严格）：必需开关必须已开，否则 NO-GO。用于"开赛那一刻"的最终确认。
  `--phase pre`（赛前演练）：必需开关是**开赛当天才设**的，赛前必然是 OFF。
    若不区分阶段，赛前跑出来永远是 NO-GO，与真实健康度无关 → 极易把"正常"误读成"故障"。
    该模式下开关只列为「待开」，GO/NO-GO 只由门禁决定。

退出码：0 = GO（可上场）；1 = NO-GO（存在阻塞项）。
"""
import os
import sys
import json
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


def find_go():
    """定位项目自带 Go 工具链（AGENTS.md 第五条：PATH 上的 go 可能不存在或版本不对）。"""
    base = os.path.join(ROOT, ".workbuddy", "toolchain", "go", "bin")
    for name in ("go.exe", "go"):
        p = os.path.join(base, name)
        if os.path.isfile(p):
            return '"%s"' % p
    return "go"


GO = find_go()


def run(cmd, timeout=900, cwd=None):
    try:
        env = dict(os.environ)
        # 三条必须独立设置（AGENTS.md 第五条）：否则 t.TempDir() 会生成非法路径
        tmpdir = env.get("SEC_TMPDIR") or "D:/tmp_gotest"
        try:
            os.makedirs(tmpdir, exist_ok=True)
        except OSError:
            pass
        env["TMP"] = tmpdir
        env["TEMP"] = tmpdir
        env["TMPDIR"] = tmpdir
        r = subprocess.run(cmd, cwd=cwd or ROOT, shell=True, encoding="utf-8",
                           errors="ignore", capture_output=True, timeout=timeout, env=env)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "超时（%ss）" % timeout
    except Exception as e:
        return 1, str(e)


def untracked_go_files():
    """未跟踪的 .go 文件（= 并行会话在途 WIP；会让磁盘活值偏离提交态）。"""
    rc, out = run("git status --porcelain", timeout=120)
    if rc != 0:
        return []
    return [l[3:].strip() for l in out.splitlines() if l.startswith("??") and l.endswith(".go")]


# 决赛推荐开关：(变量名, 是否阻塞, 说明)
SWITCHES = [
    ("CTF_POLL_ENABLED", True, "启动轮询器（不开等于不上场）"),
    ("CTF_AUTOSOLVE_SUBMIT", True, "解出即自动提交（不开要人工抄 flag）"),
    ("CTF_AUTO_BUILD_ENV", True, "需要靶机的题自动起靶机（09-17 缺口；不开 = web/pwn 主力 0 分）"),
    ("CTF_AUTO_FETCH_DETAIL", False, "题干用详情补全（列表可能是摘要）；取不到会静默回退，建议开"),
    ("CTF_AUTO_FETCH_ATTACHMENT", False, "附件题下载（DownloadAttachment 已实现骨架，附件 URL 字段名待真机校准）"),
    ("CTF_AUTO_RELEASE_ENV", False, "accepted 后回收靶机（省配额，不开不影响得分）"),
    ("CTF_ROBOT_AUTO_PREPARE", True, "IM 机器人收到题号时自动建靶机+下附件（决赛机器人辅助解题必需；不开则机器人只做本地预解）"),
]


def check_switches():
    out = []
    for name, blocking, desc in SWITCHES:
        v = os.environ.get(name, "")
        on = v.strip().lower() in ("1", "true", "yes", "on")
        out.append({"name": name, "value": v, "on": on, "blocking": blocking, "desc": desc})
    return out


# ── 凭证（2026-10-24 补）─────────────────────────────────────────────
# 实测事故：`DASCTF_BASE_URL` 与令牌**都没设置**时，预检仍输出
# 「无阻塞项 —— 可上场 / ✅ GO」。根因是 evaluate() 只看开关与门禁，
# **根本没有"凭证"这一维**；确认表虽打了 ⚠，但现场只会看最后那行结论。
# 缺凭证上场的后果是确定的：拉不到题、提交不了 flag = 0 分。
BASE_URL_ENV = "DASCTF_BASE_URL"
TOKEN_ENVS = ("DASCTF_TOKEN", "CTF_AGENT_PLATFORM_TOKEN")


def credential_issues(env=None):
    """返回 (missing, warns)。missing 非空 ⇒ final 阶段必须 NO-GO。

    只判「有没有 / 形态像不像」，**绝不回显令牌值**（日志与终端都可能被投屏）。
    """
    env = os.environ if env is None else env
    missing, warns = [], []

    base = (env.get(BASE_URL_ENV) or "").strip()
    if not base:
        missing.append("%s（平台地址）" % BASE_URL_ENV)
    else:
        if not base.lower().startswith(("http://", "https://")):
            warns.append("%s 未以 http(s):// 开头：%s" % (BASE_URL_ENV, base))
        if "/slab-match" in base:
            warns.append("%s 含 /slab-match —— 驱动会再拼一次路径、易 404；只填 host"
                         % BASE_URL_ENV)

    token, used = "", ""
    for k in TOKEN_ENVS:
        v = (env.get(k) or "").strip()
        if v:
            token, used = v, k
            break
    if not token:
        missing.append(" 或 ".join(TOKEN_ENVS) + "（Agent 令牌）")
    elif not token.startswith("ak_"):
        warns.append("%s 不以 ak_ 开头（历史实测形态为 ak_ + 约 40 位）—— "
                     "确认填的不是门户口令" % used)
    return missing, warns


# ── 鉴权实探（2026-10-24 补，opt-in：--check-auth）───────────────────
# 「凭证存在」≠「凭证可用」：实测本机环境里那把 ak_ 令牌对 pro 与 ycb-bk
# **都**返回 40403 无权操作，而 credential_issues() 只看有没有值 → 照常报 SET。
# 现场据此以为"凭证齐了"就上场，等于 0 分。本函数做一次**只读** GET（公告信息），
# 不拉题、不提交、不回显令牌。
AUTH_PROBE_PATH = "/slab-match/api/v1/agent/match/notice/match-info"
AUTH_OK_CODE = "40001"      # 参数不全 ⇒ 鉴权已通过（只是缺参数）
AUTH_DENY_CODE = "40403"    # 无权操作 ⇒ 令牌无效 / 过期 / 无该赛事权限


def classify_auth_response(http_status, body):
    """纯函数：把探测响应分类为 (verdict, detail)，verdict ∈ ok / invalid / unknown。

    抽成纯函数是为了能单测 —— 真实网络不能作为 CI 依赖。
    判定只看平台业务码，不看 HTTP 状态：DASCTF 用 200 + code 表达业务错误。
    """
    b = (body or "").replace(" ", "")
    if AUTH_DENY_CODE in b:
        return "invalid", "40403 无权操作（令牌无效/过期/无该赛事权限）"
    if AUTH_OK_CODE in b:
        return "ok", "40001 参数不全（鉴权已通过，只缺参数）"
    if http_status != 200:
        return "unknown", "HTTP %s（非 200，无法判定）" % http_status
    return "unknown", "响应无法识别：%s" % (body or "")[:120]


def probe_auth(base_url, token, timeout=15):
    """只读探测鉴权。返回 (verdict, detail)；网络异常一律归 unknown，绝不谎报红绿。"""
    import urllib.error
    import urllib.request

    url = base_url.rstrip("/") + AUTH_PROBE_PATH
    req = urllib.request.Request(
        url, headers={"X-Agent-AccessKey": token,
                      "User-Agent": "SecAutoMind-preflight/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return classify_auth_response(resp.status, resp.read(4096).decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(4096).decode("utf-8", "replace")
        except Exception:
            body = ""
        return classify_auth_response(exc.code, body)
    except Exception as exc:                       # 超时 / DNS / TLS —— 都算无法判定
        return "unknown", "网络或解析异常：%s" % type(exc).__name__


# ── CTF² 竞技场（1024 快闪赛的正式平台）──────────────────────────────────────
# 判据盲区修复（2026-10-24 实测）：本脚本原先只认 DASCTF_BASE_URL / DASCTF_TOKEN。
# 而 10-24 19:00 的正式赛跑在 CTF²（https://ctf2.dasctf.com，Bearer CTF2_AGENT_TOKEN，
# 端点前缀 /api/open/v1/user/agent/）。拿 DASCTF 的 ak_ 令牌去探 /slab-match/ 必然 40403，
# 于是输出「令牌无效」的 NO-GO —— **测的不是今晚那个平台**，属"判据用错对象"的假红。
# 差分证据：真 ak_ 令牌与伪造 ak_ 令牌对该端点返回**完全相同**的 40403，
#           只有「不带该头」才 40001 X-Agent-AccessKey —— 说明该端点不认这把令牌，
#           但也不能由此推断今晚的平台不可用（两者本就不是同一个鉴权体系）。
CTF2_BASE_ENV = "CTF2_BASE_URL"
CTF2_TOKEN_ENV = "CTF2_AGENT_TOKEN"
CTF2_COMPETITION_ENV = "CTF2_COMPETITION_ID"
CTF2_ME_PATH = "/api/open/v1/user/agent/me/?limit=1"


def pick_platform(env=None):
    """今晚真正要打的平台：CTF² 凭据齐 → ctf2，否则回退 dasctf。纯函数（可测）。"""
    env = os.environ if env is None else env
    base = (env.get(CTF2_BASE_ENV) or "").strip()
    token = (env.get(CTF2_TOKEN_ENV) or "").strip()
    return "ctf2" if (base and token) else "dasctf"


def credential_issues_ctf2(env=None):
    """CTF² 凭证判定：只判有无与形态，**绝不回显令牌值**。"""
    env = os.environ if env is None else env
    missing, warns = [], []
    base = (env.get(CTF2_BASE_ENV) or "").strip()
    token = (env.get(CTF2_TOKEN_ENV) or "").strip()
    if not base:
        missing.append("%s（CTF² 平台地址）" % CTF2_BASE_ENV)
    elif not base.lower().startswith(("http://", "https://")):
        warns.append("%s 未以 http(s):// 开头" % CTF2_BASE_ENV)
    if not token:
        missing.append("%s（CTF² Agent Bearer 令牌）" % CTF2_TOKEN_ENV)
    elif not token.startswith("ctf2_"):
        warns.append("%s 不以 ctf2_ 开头（历史形态 ctf2_ + 约 64 位）—— 确认不是别的令牌"
                     % CTF2_TOKEN_ENV)
    if not (env.get(CTF2_COMPETITION_ENV) or "").strip():
        warns.append("%s 未设置：将依赖 agent/me 自动发现比赛（调试赛与正式赛并存时可能选错）"
                     % CTF2_COMPETITION_ENV)
    return missing, warns


def classify_ctf2_auth(http_status, body=None):
    """纯函数：CTF² agent/me 响应 → (verdict, detail)；verdict ∈ ok/invalid/rate_limited/unknown。"""
    if http_status == 200:
        return "ok", "HTTP 200 agent/me 可读（Bearer 鉴权通过）"
    if http_status == 401:
        return "invalid", "HTTP 401（Bearer 令牌无效/过期）"
    if http_status == 403:
        # 与客户端口径保持一致：internal/ctfplatform/ctf2.go 的 StatusForbidden 分支把
        # 403 **一律**当作 WAF 风控（冷却 5m），不是鉴权失败。这里若判 invalid，会把
        # 「被 WAF 挡了一下」误报成「令牌坏了」，逼人去换一把其实好用的令牌。
        return "waf_blocked", "HTTP 403 WAF 风控（冷却约 5 分钟；**不能据此判定令牌无效**）"
    if http_status == 429:
        return "rate_limited", "HTTP 429（限流，未能判定 —— 勿连打）"
    return "unknown", "HTTP %s（无法判定）" % http_status


def probe_ctf2_auth(base_url, token, timeout=15):
    """只读探测 CTF² 鉴权（agent/me）。网络异常/限流一律 unknown，绝不谎报红绿。"""
    import urllib.error
    import urllib.request

    url = base_url.rstrip("/") + CTF2_ME_PATH
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
        "User-Agent": "SecAutoMind-preflight/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return classify_ctf2_auth(resp.status, resp.read(2048).decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(2048).decode("utf-8", "replace")
        except Exception:
            body = ""
        return classify_ctf2_auth(exc.code, body)
    except Exception as exc:                       # 超时 / DNS / TLS —— 都算无法判定
        return "unknown", "网络或解析异常：%s" % type(exc).__name__


def evaluate(phase, missing_blocking, hard_failures, warnings, missing_credentials=()):
    """把「门禁类硬失败」与「开关未开」「凭证缺失」分开定级，返回 (verdict, blocking, pending)。

    抽成纯函数是为了能单测：这一层若写反，脚本会给出与事实相反的 GO/NO-GO 结论，
    而门禁全绿时没人会去核对结论 —— 属最危险的"看起来能用"。

    规则：
      final 阶段（默认）：必需开关未开 = 阻塞（开赛那一刻还没开 = 上场即残废）；
                          **凭证缺失 = 阻塞**（拉不到题/提交不了 = 0 分）。
      pre   阶段：必需开关与凭证都是当天才配的，赛前缺属正常 → 只列 pending，不阻塞。
      门禁类硬失败（演练/密钥/口径/证据包/整包测试）**在两个阶段都阻塞**。
    """
    blocking = list(hard_failures)
    pending = []
    for n in missing_blocking:
        if phase == "pre":
            pending.append("当天需开：%s（赛前不阻塞）" % n)
        else:
            blocking.append("必需开关未设置：%s" % n)
    for c in missing_credentials:
        if phase == "pre":
            pending.append("开赛前需填：%s" % c)
        else:
            blocking.append("缺少凭证：%s（缺了就是拉不到题/提交不了 flag）" % c)
    verdict = "GO" if not blocking else "NO-GO"
    return verdict, blocking, pending


def parse_phase(argv):
    """解析 --phase，返回 (phase, err)。err 非 None 表示调用方应直接以 2 退出。

    单独抽出来是为了能单测：走 main() 会触发 go test（数分钟），不适合做回归测试。
    未知阶段名必须报错退出，**不静默降级成 final** —— 拼错参数还给出"看起来正常"的
    结论，是这类工具最坏的失败方式。
    """
    if "--phase" not in argv:
        return "final", None
    try:
        phase = argv[argv.index("--phase") + 1]
    except IndexError:
        return None, "--phase 缺参数（可选 pre|final）"
    if phase not in ("pre", "final"):
        return None, "--phase 只接受 pre|final，收到：%s" % phase
    return phase, None


def main():
    argv = sys.argv[1:]
    want_json = "--json" in argv
    full = "--full" in argv
    phase, phase_err = parse_phase(argv)
    if phase_err:
        print(phase_err, file=sys.stderr)
        return 2

    results = {"checks": [], "switches": check_switches(),
               "wip_untracked_go": untracked_go_files()}
    blocking_fail = []
    warnings = []

    def add(name, rc, note=""):
        results["checks"].append({"name": name, "rc": rc, "note": note.strip()[:300]})
        return rc == 0

    # ① 演练台（整链路 + 起靶机 + 附件 + 详情 + 回收）
    rc, out = run("%s test -count=1 -run TestRehearsal ./internal/ctfplatform/" % GO, timeout=900)
    ok = add("rehearsal", rc, out)
    if not ok:
        blocking_fail.append("演练台未通过（决赛整链路不可用）")

    # ② 冻结闸门状态（未武装只是提示，不算阻塞）
    rc, out = run('"%s" scripts/freeze_gate.py --status' % PY, timeout=120)
    add("freeze_gate", rc, out)

    # ③ 材料口径门禁
    #    注意：磁盘上若有并行会话未跟踪的 .go 文件，磁盘活值会偏离提交态 → 门禁必红，
    #    但 CI（干净检出）会绿。这种情况降级为警告，并说清原因（不许假装没看见）。
    rc, out = run('"%s" scripts/check_material_numbers.py' % PY, timeout=600)
    ok = add("caliber_gate", rc, out)
    if not ok:
        if results["wip_untracked_go"]:
            warnings.append("材料口径红 %d 处，但磁盘含 %d 个未跟踪 .go（在途 WIP）→ "
                            "CI 干净检出会绿；其作者提交后需重刷一次口径"
                            % (len(results["wip_untracked_go"]), len(results["wip_untracked_go"])))
        else:
            blocking_fail.append("材料口径漂移（对外数字与真值不一致）")

    # ④ 密钥门禁（交付红线）
    rc, out = run('"%s" scripts/secret_guard.py' % PY, timeout=600)
    ok = add("secret_gate", rc, out)
    if not ok:
        blocking_fail.append("密钥门禁未通过（禁止打包/上场）")

    # ⑤ 冠军证据包一致性
    #    09-28 补：此前漏检 → CI 自 09-19 起 `evidence-package-gate` 连续红（其余 job 全绿，
    #    极易被误判为偶发）。证据包必须随任何改变对外数字的提交同步重生成。
    rc, out = run('"%s" scripts/build_championship_evidence.py --check' % PY, timeout=900)
    ok = add("evidence_package", rc, out)
    if not ok:
        if results["wip_untracked_go"]:
            warnings.append("证据包与磁盘活值不一致，但磁盘含 %d 个未跟踪 .go（在途 WIP）→ "
                            "CI 干净检出可能绿；WIP 提交后需重生成证据包"
                            % len(results["wip_untracked_go"]))
        else:
            blocking_fail.append("冠军证据包过期（CI evidence-package-gate 会 BLOCK）—— "
                                 "跑 `python scripts/build_championship_evidence.py` 重生成")

    # ⑤ 可选：整包 go test
    if full:
        rc, out = run("%s test -count=1 ./..." % GO, timeout=3600)
        ok = add("go_test_full", rc, out)
        if not ok:
            blocking_fail.append("整包测试未全绿")

    # ⑥ 开关检查结论（按阶段定级，见 evaluate）
    missing_blocking = [s["name"] for s in results["switches"] if s["blocking"] and not s["on"]]

    # ⑦ 凭证（**按今晚实际平台判定**）：缺了开赛即 0 分，final 阶段必须阻塞
    platform = pick_platform()
    results["platform"] = platform
    if platform == "ctf2":
        missing_creds, cred_warns = credential_issues_ctf2()
        base_set = bool((os.environ.get(CTF2_BASE_ENV) or "").strip())
        token_set = bool((os.environ.get(CTF2_TOKEN_ENV) or "").strip())
        base_name, token_name = CTF2_BASE_ENV, CTF2_TOKEN_ENV
        if (os.environ.get(BASE_URL_ENV) or "").strip():
            warnings.append("同时配置了 %s：今晚平台是 CTF²，该地址仅作战备用"
                            "（其令牌对 /slab-match/ 返回 40403 属正常，不代表今晚不可用）"
                            % BASE_URL_ENV)
    else:
        missing_creds, cred_warns = credential_issues()
        base_set = bool((os.environ.get(BASE_URL_ENV) or "").strip())
        token_set = any((os.environ.get(k) or "").strip() for k in TOKEN_ENVS)
        base_name, token_name = BASE_URL_ENV, "/".join(TOKEN_ENVS)
    warnings.extend(cred_warns)
    results["credentials"] = {
        "platform": platform,
        "base_url_set": base_set,
        "token_set": token_set,
        "base_env": base_name,
        "token_env": token_name,
        "missing": missing_creds,
    }

    # ⑧ 可选：鉴权实探（--check-auth）——「存在」不等于「可用」；按平台派发
    auth_probe = None
    if "--check-auth" in argv:
        if platform == "ctf2":
            base = (os.environ.get(CTF2_BASE_ENV) or "").strip()
            token = (os.environ.get(CTF2_TOKEN_ENV) or "").strip()
            if not base or not token:
                warnings.append("--check-auth 已请求，但缺 CTF² 地址或令牌 → 未实探")
            else:
                verdict_a, detail_a = probe_ctf2_auth(base, token)
                auth_probe = {"verdict": verdict_a, "detail": detail_a,
                              "base_url": base, "platform": "ctf2"}
                if verdict_a == "invalid":
                    blocking_fail.append("CTF² 令牌鉴权失败：%s（--check-auth 实测 %s）"
                                         % (detail_a, base))
                elif verdict_a in ("unknown", "rate_limited", "waf_blocked"):
                    warnings.append("--check-auth 无法判定（%s）—— 需人工确认，"
                                    "**不要据此更换令牌**" % detail_a)
        else:
            base = (os.environ.get(BASE_URL_ENV) or "").strip()
            token = ""
            for k in TOKEN_ENVS:
                v = (os.environ.get(k) or "").strip()
                if v:
                    token = v
                    break
            if not base or not token:
                warnings.append("--check-auth 已请求，但缺地址或令牌 → 未实探")
            else:
                verdict_a, detail_a = probe_auth(base, token)
                auth_probe = {"verdict": verdict_a, "detail": detail_a,
                              "base_url": base, "platform": "dasctf"}
                if verdict_a == "invalid":
                    blocking_fail.append("令牌鉴权失败：%s（--check-auth 实测 %s）"
                                         % (detail_a, base))
                elif verdict_a == "unknown":
                    warnings.append("--check-auth 无法判定（%s）—— 需人工确认" % detail_a)
    results["auth_probe"] = auth_probe

    # ── ⑨ Python skill 依赖（runner Layer 2 硬依赖）──────────────────
    # 2026-10-24 补：西湖论剑复盘揭示 runner Layer 2（angr/pwntools）
    # 静默跳过的风险——CLI 启动时只打印"pwntools:false"，不会阻塞，但
    # reverse/pwn 题因此 0 分。CI 环境没装 angr 属正常 → 警告级；
    # final 阶段（开赛那一刻）升级为阻塞。
    def check_py_dep(name, import_path=None):
        imp = import_path or name
        rc, out = run('%s -c "import importlib.util; print(\'OK\' if importlib.util.find_spec(\'%s\') else \'MISSING\')"' % (PY, imp), timeout=15)
        return rc == 0 and "OK" in out

    py_issues = []
    if not check_py_dep("angr"):
        py_issues.append("angr（符号执行）")
    if not check_py_dep("pwntools", "pwnlib"):
        py_issues.append("pwntools（import pwnlib）")
    if py_issues:
        msg = "Python 依赖缺失：%s — runner Layer 2 会跳过 reverse/pwn 真解" % ", ".join(py_issues)
        if phase == "final":
            blocking_fail.append(msg)
        else:
            warnings.append(msg + "（pre 阶段只警告）")

    # ── ⑩ 进程冲突（同一个 token 被两个进程用 → 429/封禁）──────────────
    # 2026-10-24 补：快闪赛 ctf-agent（E:\Program\ctf-agent）与 SecAutoMind runner
    # 同时跑，若用同一 CTF2_AGENT_TOKEN，平台会限流或封禁。
    # 只在 final 阶段阻塞；pre 阶段只警告。
    def proc_count(pattern):
        import subprocess as _sp
        try:
            if os.name == "nt":
                # Windows：tasklist /FI 精确匹配进程名（含 .exe）
                r = _sp.run(["tasklist", "/FI", "IMAGENAME eq %s.exe" % pattern],
                           capture_output=True, text=True, timeout=5)
                return max(0, r.stdout.count(pattern + ".exe") - 1)
            else:
                # Linux：pgrep -f 模糊匹配命令行
                r = _sp.run(["pgrep", "-f", pattern], capture_output=True, text=True, timeout=5)
                return len([l for l in (r.stdout or "").splitlines() if l.strip()])
        except Exception:
            return 0

    # 额外查 ctf-agent 进程（Python final_entry.py 或 runner_ctf2.py）
    def py_proc_count(pattern):
        """查 python 进程命令行里包含 pattern 的数量。"""
        import subprocess as _sp
        try:
            if os.name == "nt":
                r = _sp.run(["wmic", "process", "where",
                              "name='python.exe' or name='python3.exe'",
                              "get", "CommandLine"],
                           capture_output=True, text=True, timeout=8)
                return sum(1 for line in (r.stdout or "").splitlines()
                           if pattern.lower() in line.lower())
            else:
                r = _sp.run(["pgrep", "-f", pattern], capture_output=True, text=True, timeout=5)
                return len([l for l in (r.stdout or "").splitlines() if l.strip()])
        except Exception:
            return 0

    runner_procs = proc_count("runner_ctf") + proc_count("runner")
    ctf_agent_procs = py_proc_count("final_entry") + py_proc_count("runner_ctf2")
    # runner_cli 在服务器上也叫 runner_ctf（Linux 没 .exe）
    if os.name != "nt":
        runner_procs = proc_count("runner_ctf") + proc_count("runner") + py_proc_count("runner_ctf")
    total_conflict = runner_procs + ctf_agent_procs
    if total_conflict > 0:
        msg = "检测到参赛进程：runner=%d, ctf-agent=%d — 多进程共用 token 会触发 429 限流" % (
            runner_procs, ctf_agent_procs)
        if phase == "final":
            blocking_fail.append(msg)
        else:
            warnings.append(msg + "（pre 阶段只警告）")

    results["warnings"] = warnings
    results["phase"] = phase
    verdict, blocking_fail, pending = evaluate(phase, missing_blocking, blocking_fail, warnings,
                                               missing_credentials=missing_creds)
    results["verdict"] = verdict
    results["blocking"] = blocking_fail
    results["pending"] = pending

    if want_json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0 if verdict == "GO" else 1

    phase_desc = "赛前演练（当天才开的开关不阻塞）" if phase == "pre" else "开赛最终确认（必需开关必须已开）"
    print("=" * 74)
    print("决赛赛前预检 · %s  ·  阶段=%s（%s）" % (results["verdict"], phase, phase_desc))
    print("=" * 74)
    print("\n[开关]")
    for s in results["switches"]:
        mark = "ON " if s["on"] else "OFF"
        need = "必需" if s["blocking"] else "可选"
        print("  [%s/%s] %-28s %s" % (mark, need, s["name"], s["desc"]))
    plat_desc = ("CTF2 竞技场" if results["platform"] == "ctf2" else "DASCTF（/slab-match）")
    print("")
    print("[凭证]  今晚平台 = %s" % plat_desc)
    cred = results["credentials"]
    print("  [%s] %-28s %s" % ("SET " if cred["base_url_set"] else "MISS",
                               cred["base_env"], "平台地址"))
    print("  [%s] %-28s %s" % ("SET " if cred["token_set"] else "MISS",
                               cred["token_env"], "Agent 令牌（值不回显）"))
    if results.get("auth_probe"):
        ap = results["auth_probe"]
        print("  [%-4s] %-28s %s" % (ap["verdict"].upper()[:4], "鉴权实探(--check-auth)",
                                     ap["detail"]))
    print("\n[检查项]")
    for c in results["checks"]:
        print("  [%s] %-16s rc=%d" % ("OK" if c["rc"] == 0 else "FAIL", c["name"], c["rc"]))
    if warnings:
        print("\n[警告（不阻塞）]")
        for w in warnings:
            print("  ! %s" % w)
    if pending:
        print("\n[待开（%s 阶段不阻塞）]" % phase)
        for p in pending:
            print("  ○ %s" % p)
    if blocking_fail:
        print("\n[阻塞项]")
        for f in blocking_fail:
            print("  ✗ %s" % f)
    else:
        print("\n  无阻塞项 —— 可上场。")
    print("\n" + "=" * 74)
    return 0 if verdict == "GO" else 1


if __name__ == "__main__":
    os.environ.setdefault("APPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Roaming"))
    sys.exit(main())
