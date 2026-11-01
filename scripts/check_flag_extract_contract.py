#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""flag 提取「跨语言单一真值源」契约（cross-language golden test 的 Python 半边）。

为什么需要它（2026-10-30 建立，防 10-29 冤案复发）：
    Python 侧 scripts/experiments/flag_util.py::FLAG_RE 与 Go 侧
    internal/runnerl3/llm_solver.go::flagCandRe 目前**字面量相同**，但却是各自
    硬编码的两份拷贝 —— 改一侧另一侧不会有任何报警。10-29 服务器真机事故的
    根因就是两侧口径各活各的（Go 侧旧实现 strings.Index("flag{") 只认一种前缀，
    模型已输出 picoCTF{...} 正解却判「没找到 flag 格式」→ MISS）。
    另有更细的既有差异：Python extract_candidates 直接 findall **不去重**，
    Go extractFlagCandidates 带 seen map **去重** + TrimSpace。今天不影响判分
    （两侧最终都只认 flag_sha256），但没有任何机器契约锁住「哪些 token 算候选」。

设计（照抄仓库既有的 protocol_golden 范式，真值是 Python 侧）：
    - 真值源 = flag_util.FLAG_RE。本脚本用它在内置 CASES 上跑出「按首次出现去重」
      的候选列表，冻结进 internal/runnerl3/testdata/flag_extract_golden.json。
    - Python --check：用当前 FLAG_RE 重算，与冻结 golden 逐例比对，漂移即 rc=1
      ⇒ 锁住 Python 侧（有人改正则忘了同步 golden 会红）。
    - Go internal/runnerl3/contract_flag_extract_test.go：读同一份 golden，
      断言 extractFlagCandidates 归一化结果逐例相等 ⇒ 锁住 Go 侧
      （有人改 Go 正则忘了同步 golden 也会红）。
    ⇒ 任何一侧单独改动都会让契约红，必须两侧 + golden 一起改才放行。

归一化口径（两侧对称，写死别改）：
    1. 用各自正则从左到右抽取全部匹配；
    2. 每个匹配 strip 掉首尾空白（正则匹配本就以字母开头、} 结尾，正常是 no-op，
       仅为与 Go 的 TrimSpace 严格对齐）；
    3. 按**首次出现顺序去重**（Go 侧 seen map 的语义）。
    顺序：两侧都是确定性左到右，去重都保留首次出现，故可严格逐项比对；
    且下游判分只看 sha256、本就与顺序无关，逐项相等是更强的约束。

用法：
    python scripts/check_flag_extract_contract.py --generate   # 依据当前真值源刷新 golden
    python scripts/check_flag_extract_contract.py --check      # 比对（供 CI），漂移 rc=1
    python scripts/check_flag_extract_contract.py --selftest   # 变异验证：故意破坏必须被抓
    python scripts/check_flag_extract_contract.py              # 默认 == --check

⚠️ 纪律：golden 是派生产物，禁止手改；改了 FLAG_RE 必须 --generate 并让 Go 侧同步通过。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

# AGENTS.md 第五条实锤：本地 Windows GBK 控制台对含中文/emoji 的输出直接
# UnicodeEncodeError → rc=1 假红。CI 的 ubuntu 默认 UTF-8 不受影响。
# 与其他新一代门禁（check_golden_freeze.py 等）一致，自带 UTF-8 兜底。
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:  # pragma: no cover - 非交互/已重定向时可能不支持
    pass

REPO = Path(__file__).resolve().parent.parent
EXPERIMENTS = REPO / "scripts" / "experiments"
GOLDEN = REPO / "internal" / "runnerl3" / "testdata" / "flag_extract_golden.json"

# 让 import flag_util 命中 scripts/experiments（真值源唯一入口）
if str(EXPERIMENTS) not in sys.path:
    sys.path.insert(0, str(EXPERIMENTS))

try:
    from flag_util import FLAG_RE  # 真值源
except Exception as exc:  # pragma: no cover - 环境问题要显式暴露，不能静默降级
    raise SystemExit(f"导入真值源 flag_util.FLAG_RE 失败: {exc}") from exc


# ── 内置 CASES：(name, input) ──
# 覆盖：真实题库出现过的全部前缀形态、大小写、去重、边界长度、未闭合/空/嵌套/换行、
# 以及 10-29 事故原题。expected 不手写，一律由真值源 FLAG_RE 现算，避免人肉口径漂移。
CASES: list[tuple[str, str]] = [
    ("flag_standard",        "答案是 flag{abc_123}，请提交"),
    ("picoCTF_事故原题",      "解出 picoCTF{caesar_d3cr9pt3d_f0212758}\n\nCONFIDENCE: 1.0"),
    ("sdctf_含特殊字符",       "sdctf{Case64_ar!}"),
    ("CBCV_前缀",             "CBCV{dGhpcyBpcyBiYXNlNjQ=}"),
    ("wctf_前缀",             "wctf{xor_known_plaintext}"),
    ("grodno_前缀",           "grodno{Gr0dn0_CTF_2021}"),
    ("DASCTF_前缀",           "DASCTF{c0rr3ct_answ3r}"),
    ("BZHCTF_前缀",           "BZHCTF{prefix_rewritten}"),
    ("upper_FLAG",            "FLAG{UPPER}"),
    ("mixed_Flag",            "Flag{MiXeD_CaSe}"),
    ("flag_引导词",            "flag: flag{led}"),
    ("多候选去重",             "flag{a}\nflag{a}\nflag{b}"),
    ("多前缀混排",             "picoCTF{first} 和 sdctf{second} 还有 flag{third}"),
    ("无花括号文本",           "CONFIDENCE: 1.0 没有 flag 也没有答案"),
    ("未闭合不算候选",         "flag{unclosed 后面没了"),
    ("空内容不算候选",         "flag{}"),
    ("内容含换行不跨界",       "flag{line1\nline2}"),
    ("嵌套花括号",             "flag{a{b}"),
    ("内容含空格",             "flag{has space inside}"),
    ("前缀最长15字符",         "ABCDEFGHIJKLMNO{p15}"),   # 1+14=15，整串匹配
    ("前缀16字符触发回退",     "ABCDEFGHIJKLMNOP{p16}"),  # 16 字符：左侧起点后移，验证两侧正则引擎一致
    ("下划线数字前缀",         "X_123{underscore_digit}"),
    ("单字母前缀",             "x{single}"),
    ("数字开头不算前缀",       "123flag{no_digit_start}"),  # 数字后是 f..g{..}，应从 f 起匹配
    ("超200字符内容",          "flag{" + "a" * 201 + "}"),  # 超上限，不整串匹配
    ("末尾无闭合",             "flag{no_close"),
    ("中文叙述夹候选",         "经过计算，最终 flag{cn_中文_内容_123} 就是这个"),
]


def _ordered_unique(matches: list[str]) -> list[str]:
    """归一化：strip + 按首次出现顺序去重（与 Go 侧 extractFlagCandidates 对齐）。"""
    out: list[str] = []
    seen: set[str] = set()
    for raw in matches:
        s = raw.strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def extract_normalized(text: str) -> list[str]:
    """用真值源正则跑一遍并归一化 —— golden 的 expected 就是这么来的。"""
    return _ordered_unique(FLAG_RE.findall(text or ""))


def build_golden() -> dict:
    cases = [
        {"name": name, "input": text, "expected": extract_normalized(text)}
        for name, text in CASES
    ]
    return {
        "_comment": "flag 提取跨语言契约。由 scripts/check_flag_extract_contract.py "
                    "依据真值源 flag_util.FLAG_RE 生成，禁止手改。",
        "_normalization": "左右抽取 → 每个匹配 strip → 按首次出现去重；两侧必须逐项相等。",
        "_truth_source": "scripts/experiments/flag_util.py::FLAG_RE "
                         r"[A-Za-z][A-Za-z0-9_]{0,14}\{[^{}\n]{1,200}\}",
        "source_regex": FLAG_RE.pattern,
        "cases": cases,
    }


def _read_golden() -> dict:
    if not GOLDEN.exists():
        raise SystemExit(f"[FAIL] golden 不存在: {GOLDEN}\n请先跑 --generate")
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


def do_generate() -> int:
    golden = build_golden()
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n"：防 Windows 下写 CRLF，与 Linux CI / Go 侧读取的行尾一致。
    with open(GOLDEN, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(golden, ensure_ascii=False, indent=2) + "\n")
    print(f"[OK] golden 已生成: {GOLDEN}")
    print(f"     用例 {len(golden['cases'])} 条 / 正则 {golden['source_regex']!r}")
    # 顺带打印每例抽取结果，便于人眼核对（不打印任何真值 flag，只是候选形态）
    for c in golden["cases"]:
        print(f"     - {c['name']:<22} -> {c['expected']}")
    print("     ⚠️ 接着必须在 Go 侧跑 go test ./internal/runnerl3/ 让契约测试通过")
    return 0


def do_check() -> int:
    golden = _read_golden()
    # 锁正则字面量本身：连 pattern 字符串都不许单独漂移
    if golden.get("source_regex") != FLAG_RE.pattern:
        print(f"[FAIL] 真值源正则已变：golden={golden.get('source_regex')!r} "
              f"当前 FLAG_RE={FLAG_RE.pattern!r}，请确认后 --generate")
        return 1
    diffs = 0
    for c in golden["cases"]:
        got = extract_normalized(c["input"])
        if got != c["expected"]:
            print(f"[DIFF] {c['name']}: golden={c['expected']} 当前真值源={got}")
            diffs += 1
    if diffs:
        print(f"[FAIL] {diffs} 处与冻结 golden 不一致（真值源行为已变）；"
              f"如属预期改动，请 --generate 并同步 Go 侧。")
        return 1
    print(f"[OK] flag 提取契约一致：{len(golden['cases'])} 条用例，正则 {FLAG_RE.pattern!r}")
    # 跨语言 golden 过了还不够：仓库内另外 20+ 份拷贝也要锁住（CI 的 --check 因此覆盖两处）
    return do_check_copies()


# ── 拷贝一致性（2026-10-31 加）：跨语言契约只锁住了 flag_util ↔ Go 两侧 ──
#
# 🔴 实锤：真值源之外，仓库里还有 20+ 份**独立硬编码**的 flag 候选正则，三种口径并存：
#     判分侧  {1,200}：flag_util / stepfun_batch_server / sanitize_conversations_db
#     门禁侧  {6,200}：preflight_answer_leak / db_plaintext_diag / leak_audit / leak_scan_list
#     清除侧  {6,200}：redact_prompt_answers / sanitize_plaintext
#     跑批侧  {3,90} ：stepfun_s2_freekey（这个是判分用的！）/ benchmark_selfcheck_v2
#   漂移方向最坏：**负责清除答案的工具比判分工具窄** ⇒
#   「库里 0 命中 / 文件里 0 命中」只证明「没有长 flag」，短 flag 与超长 flag 仍在磁盘上。
#   实测代价：扫 8 个实例库，含空格的真 flag 被窄口径整条漏掉 143 处（2293 vs 2436，6.2%）。
#
# 本检查与跨语言 golden 契约**共用同一条判分口径**，把「拷贝漂移」变成 CI 可见的红。

COPY_PREFIX = "[A-Za-z][A-Za-z0-9_]{0,14}"
# 变体前缀：遮蔽器/扫描器里常见的括号捕获写法（build_cross_bench.FLAG_CAND_RE 曾用）。
# 它长得不像 COPY_PREFIX，故 v1 的扫描器**看不见它** —— 2026-10-31 因此漏掉了
# 「判分认、遮蔽器不认」的 4 种绕过形态。两种前缀都要扫。
ALT_PREFIX = "([A-Za-z0-9_]{2,})\\{"
SPAN_RE = re.compile(r"\{(\d+),(\d+)\}")
SCAN_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".workbuddy",
                  "CTF-Agent_融合", "dist", "miniconda3", "venv"}

# 已备案的「有意不同」：路径后缀 → 理由（**必须非空**，否则本豁免变成静默放水）。
#
# 判据不是「所有拷贝都必须一样」，而是分两类：
#   · 清除型（脱敏/遮蔽/擦除，如 sanitize_* / build_*_bench）：必须**至少**认得判分认得的全部形态，
#     否则就是「重跑一次 = 再泄一次」 ⇒ 不同即阻断。
#   · 检测型（扫描告警，如 secret_guard）：还要额外权衡**误报成本**，
#     窄口径可能是有意的噪声防线 ⇒ 允许备案豁免，但每次都要把理由与代价打出来。
ACCEPTED_VARIANTS = {
    "scripts/secret_guard.py": (
        "检测型扫描器的窄口径是有意的噪声防线：字符类禁引号/空格/冒号/分号，"
        "专门避开 Go 结构体字面量。实测 400 个文件（internal/**/*.go + scripts/*.py）："
        "改用判分口径会多出 **1039 个候选**（170 → 1208，约 7 倍），"
        "多出的几乎全是 `AgentConfig{MaxIterations: 12000}` 之类噪声。"
        "⇒ 不改。代价（记录在案的盲区）：看不见**含空格**与**内文 2~3 字符**的 flag 明文；"
        "而本仓库语料里确实存在含空格的真 flag，故此盲区是**已知风险**，不是该改的漂移。"
    ),
}


def scan_regex_copies(root: Path):
    r"""扫描 root 下 .py，返回与判分口径不符的拷贝 [(file, line, kind, reason)]。

    只锁「带长度约束的候选抽取正则」；形如 `^(...)\{(.*)\}$` 的分裂正则
    （无 {n,m}）不在此列，故跳过——避免把正常代码判成漂移。
    """
    bad = []
    if not root.is_dir():
        return bad
    for p in sorted(root.rglob("*.py")):
        if SCAN_SKIP_DIRS & set(p.parts):
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, ln in enumerate(lines, 1):
            # 只认**真正创建正则**的行：注释/文档里引用旧正则是很常见的写法
            # （2026-10-31 实锤：把 build_cross_bench 注释里的旧 {4,80} 当现役正则报了假红）
            if not (("re.compile" in ln) or ("MustCompile" in ln)
                    or re.search(r"\b[A-Za-z_]*RE\s*=\s*r?[\"']", ln)):
                continue
            if COPY_PREFIX in ln:
                rest = ln.split(COPY_PREFIX, 1)[1]
            elif ALT_PREFIX in ln:
                rest = ln.split(ALT_PREFIX, 1)[1]
            else:
                continue
            # 必须先切掉前缀：前缀自身含 {0,14}，不切会被当成内长而误报
            m = SPAN_RE.search(rest)
            if not m:
                continue
            span = (int(m.group(1)), int(m.group(2)))
            grep_form = "[{]" in ln
            why = []
            if span != (1, 200):
                why.append("内长 {%d,%d} ≠ {1,200}" % span)
            if grep_form:
                # grep 逐行处理，无需排除换行；字符类统一 [^{}]
                if "[^{}]" not in ln:
                    why.append("字符类不是 [^{}]（grep 形态）")
            elif "[^{}\\n]" not in ln:
                why.append("字符类不是 [^{}\\n]")
            if why:
                try:
                    rel = p.relative_to(root.parent).as_posix()
                except ValueError:
                    rel = p.as_posix()
                bad.append((rel, i, "grep" if grep_form else "python", "；".join(why)))
    return bad


def do_check_copies() -> int:
    roots = [REPO / "scripts", REPO / "data"]
    bad, accepted = [], []
    for r in roots:
        for item in scan_regex_copies(r):
            if any(item[0].endswith(k) for k in ACCEPTED_VARIANTS):
                accepted.append(item)
            else:
                bad.append(item)
    for f, i, kind, why in accepted:
        print("[备案豁免] %s:%d [%s] %s" % (f, i, kind, why))
        print("           理由：%s" % ACCEPTED_VARIANTS[
            next(k for k in ACCEPTED_VARIANTS if f.endswith(k))])
    if bad:
        print("[FAIL] %d 处 flag 正则拷贝与判分口径不一致（判分口径 %r）："
              % (len(bad), FLAG_RE.pattern))
        for f, i, kind, why in bad[:40]:
            print("  %s:%d [%s] %s" % (f, i, kind, why))
        print("  ⇒ 清除侧比判分侧窄 = 「0 命中」只证明没有长 flag。一律改成 {1,200}。")
        return 1
    print("[OK] flag 正则拷贝一致：仓库内各拷贝与判分口径逐份相符")
    return 0


def do_selftest() -> int:
    """变异验证：证明本契约确实能抓住漂移，而不是恒绿摆设。"""
    ok = True

    # 1) 正常 golden 必须通过 check 逻辑
    golden = build_golden()
    clean_pass = all(
        extract_normalized(c["input"]) == c["expected"] for c in golden["cases"]
    )
    ok &= clean_pass
    print(f"[1] 未变异时逐例自洽 -> {clean_pass} (应 True)")

    # 2) 变异 A：篡改某个 expected（模拟 golden 与真值源脱节）必被 check 抓到
    tampered = json.loads(json.dumps(golden, ensure_ascii=False))
    tampered["cases"][0]["expected"] = ["flag{INJECTED_DIFFERENT}"]
    caught_a = any(
        extract_normalized(c["input"]) != c["expected"] for c in tampered["cases"]
    )
    ok &= caught_a
    print(f"[2] 变异(篡改 expected)被抓 -> {caught_a} (应 True)")

    # 3) 变异 B：把真值源正则临时换成旧的「只认 flag{} 小写」→ picoCTF 用例必漂移
    import re
    original = FLAG_RE
    import flag_util
    try:
        flag_util.FLAG_RE = re.compile(r"flag\{[^{}]{1,200}\}")  # 旧口径
        # extract_normalized 引用的是模块级 FLAG_RE，需绕开已绑定的局部名
        def extract_with(reg, text):
            return _ordered_unique(reg.findall(text or ""))
        pico = next(c for c in golden["cases"] if c["name"] == "picoCTF_事故原题")
        caught_b = extract_with(flag_util.FLAG_RE, pico["input"]) != pico["expected"]
        ok &= caught_b
        print(f"[3] 变异(正则退回旧口径)picoCTF 用例漂移被抓 -> {caught_b} (应 True)")
    finally:
        flag_util.FLAG_RE = original

    # 4) 事故回归护栏：真值源正则必须能抽出 picoCTF{}（10-29 冤案原题）
    import flag_util as _fu
    pico_hit = _ordered_unique(_fu.FLAG_RE.findall(
        "picoCTF{caesar_d3cr9pt3d_f0212758}")) == ["picoCTF{caesar_d3cr9pt3d_f0212758}"]
    ok &= pico_hit
    print(f"[4] 事故回归：真值源正则抽得 picoCTF 候选 -> {pico_hit} (应 True)")

    # 5) 去重语义：重复候选只保留一次（Go/Python 归一化一致的关键）
    dedup = extract_normalized("flag{a}\nflag{a}\nflag{b}")
    ok &= (dedup == ["flag{a}", "flag{b}"])
    print(f"[5] 归一化去重语义 -> {dedup} (应 ['flag{{a}}','flag{{b}}'])")

    # 6) 变异 C：仓库里多一份 {6,200} 的漂移拷贝，拷贝扫描必须抓到
    with tempfile.TemporaryDirectory() as td:
        drift = ('FLAG_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,14}'
                 r'\{[^{}\n]{6,200}\}' + '")')
        (Path(td) / "mutant.py").write_text(drift + "\n", encoding="utf-8")
        got = scan_regex_copies(Path(td))
        caught_c = len(got) == 1 and "6,200" in got[0][3]
    ok &= caught_c
    print(f"[6] 变异(拷贝内长漂到 6,200)被抓 -> {caught_c} (应 True)")

    # 7) 反向：合规拷贝不许误报（否则扫描器会把正常代码判成漂移而变红）
    with tempfile.TemporaryDirectory() as td:
        clean = ('FLAG_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,14}'
                 r'\{[^{}\n]{1,200}\}' + '")')
        (Path(td) / "clean.py").write_text(clean + "\n", encoding="utf-8")
        no_false = scan_regex_copies(Path(td)) == []
    ok &= no_false
    print(f"[7] 合规拷贝不误报 -> {no_false} (应 True)")

    # 8) 变异 D：变体前缀（遮蔽器的括号捕获写法）被收窄，也必须被抓到
    with tempfile.TemporaryDirectory() as td:
        narrow = ('CAND = re.compile(r"([A-Za-z0-9_]{2,})'
                  r'\{[^}\n]{4,80}\}")')
        (Path(td) / "mutant2.py").write_text(narrow + "\n", encoding="utf-8")
        got = scan_regex_copies(Path(td))
        caught_d = len(got) == 1 and "4,80" in got[0][3]
    ok &= caught_d
    print(f"[8] 变异(变体前缀内长收窄到 4,80)被抓 -> {caught_d} (应 True)")

    # 9) 反向：变体前缀改用判分口径后不误报（否则修好的人会被自己的门禁拦住）
    with tempfile.TemporaryDirectory() as td:
        wide = ('CAND = re.compile(r"([A-Za-z][A-Za-z0-9_]{0,14})'
                r'\{[^{}\n]{1,200}\}")')
        (Path(td) / "clean2.py").write_text(wide + "\n", encoding="utf-8")
        no_false2 = scan_regex_copies(Path(td)) == []
    ok &= no_false2
    print(f"[9] 变体前缀合规不误报 -> {no_false2} (应 True)")

    # 10) 备案豁免要真的生效（否则 secret_guard 那条会静默阻断 CI）
    narrow = ('FLAG_CAND_RE = re.compile(r"([A-Za-z0-9_]{2,})'
              r'\{[^}\n\":; ]{4,200}\}")')
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "scripts"
        d.mkdir()
        (d / "secret_guard.py").write_text(narrow + "\n", encoding="utf-8")
        items = scan_regex_copies(d)
        exempted = (len(items) == 1
                    and any(items[0][0].endswith(k) for k in ACCEPTED_VARIANTS)
                    and all(ACCEPTED_VARIANTS.values()))
    ok &= exempted
    print(f"[10] 备案豁免生效（secret_guard 不阻断、理由非空） -> {exempted} (应 True)")

    # 11) 反向：豁免是**按名**生效的，换个名字的清除型工具照样必须阻断
    #     （否则「豁免」就退化成全局放水，等于把门禁拆了）
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "scripts"
        d.mkdir()
        (d / "sanitize_something.py").write_text(narrow + "\n", encoding="utf-8")
        items = scan_regex_copies(d)
        still_blocks = (len(items) == 1
                        and not any(items[0][0].endswith(k) for k in ACCEPTED_VARIANTS))
    ok &= still_blocks
    print(f"[11] 同一窄正则换名后仍阻断（豁免不是放水） -> {still_blocks} (应 True)")

    print("\nSELFTEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="flag 提取跨语言一致性契约")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--generate", action="store_true", help="依据真值源刷新 golden")
    g.add_argument("--check", action="store_true", help="只比对不写入（CI），漂移 rc=1")
    g.add_argument("--selftest", action="store_true", help="变异验证契约有效性")
    args = ap.parse_args()

    if args.generate:
        return do_generate()
    if args.selftest:
        return do_selftest()
    return do_check()  # 默认 == --check


if __name__ == "__main__":
    sys.exit(main())
