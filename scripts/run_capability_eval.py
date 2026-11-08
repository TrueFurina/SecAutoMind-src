#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""合规能力评测入口：前置守卫 → 跑批 → 自动证据 → 判分仲裁。

为什么要有这个入口（评审 §12）：
  - 上一版判据的 evidence.json **由人填**，填假仍会误判（§11.4 已承认的边界）；
  - 启动器 `_run_purellm_176.py` 没有任何开关前置，三条件全缺照跑；
  - 因此把「开关 + 池指纹 + 门禁 + 判据」收进同一个不可绕过的入口，
    证据由入口从 env / 源码 / 指纹自动生成，而不是事后手写。

口径（必须写清，否则证据自相矛盾）：
  - airgap 的「零外网」指**解题子进程**（python_session / skill / 流式 shell）经
    syscall 隔离；**LLM API 通道本身必须联网**，不在隔离范围内，否则无法调用模型。
  - 判闸门是否生效**只能用 IP 直连证明**（DNS 失败与没配 DNS 同形），所以要求
    `--airgap-proof` 里 ip_direct_blocked=true 且 af_unix_ok=true。
  - §18：上面两条只是**机制层**证据。proof 自身 caveats 声明「只证明闸门在探测
    二进制生效，不证明任何一次跑批真的开了闸」，且作用域是 Go 侧 python_session；
    Python orchestrator 的 run_python_tool 是另一条未隔离子进程（实测 CTF_AIRGAP=1
    下仍可 IP 直连）。故 agentic 额外要求 `run_binding` 把证据绑定到本次跑批命令
    及其解题子进程，缺则 fail-closed。
  - temperature：orchestrator 两处请求体硬编码 0.2 ⇒ 随机源「显式固定」代码级可证；
    但这**不等于逐位可复现**（provider 采样/版本会变），判据只要求显式固定值。

用法：
  python scripts/run_capability_eval.py --preflight
  python scripts/run_capability_eval.py --adjudicate <result.json>
  python scripts/run_capability_eval.py --run --result <result.json> -- <cmd...>
  # 换池必须三个参数同步换，否则 claim_scope=unverified / 前置守卫拒绝：
  python scripts/run_capability_eval.py --run --pool <池> --manifest <manifest> \
      --prior-audit <题源证据> --result <r.json> -- <cmd...（--benchmark 须同池）>
  # 给已有 verdict 追加结论作用域与判分假阴性片段（只加字段、逐键校验不改判分）：
  python scripts/run_capability_eval.py --annotate <verdict.json> --gap-result <r.json>
  # 私有性外部锚点契约（题面自证不采信；未达成时禁止发布能力率）：
  python scripts/audit_private_proof.py --selftest | --check | --verify | --require-proof
退出码：前置不通过 = 2；判分不可归因 = 1；全绿 = 0。

§17：能力率的发布前提不是「池里写满了 private」，而是私有性有可复核的外部
锚点（git 首次提交时间戳 + 内容指纹 + 公开真值排除）。claim_scope 由代码重算，
无锚点时无论题面怎么标都强制 engineering_regression_only。
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_benchmark_plaintext_answer import (analyze, violations,  # noqa: E402
                                              self_disclosure_in_statement)
from check_pure_llm_caliber import (EVIDENCE_KEYS, PURE_LLM_EVIDENCE_KEYS,  # noqa: E402
                                   evidence_keys, judge_run, load_leak_ids,
                                   load_questions, load_trained_ids,
                                   prove_pure_llm_path, selftest)
import audit_pool_prior  # noqa: E402
import audit_writeup_answer  # noqa: E402
import audit_scoring_variant_gap  # noqa: E402
import audit_private_proof  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POOL = os.path.join(ROOT, "data", "ctf_benchmark", "purellm_clean_benchmark.json")
MANIFEST = os.path.join(ROOT, "data", "ctf_benchmark", "purellm_clean_benchmark.manifest.json")
POOL_V2 = os.path.join(ROOT, "data", "ctf_benchmark", "purellm_clean_benchmark_v2.json")
MANIFEST_V2 = os.path.join(ROOT, "data", "ctf_benchmark",
                           "purellm_clean_benchmark_v2.manifest.json")
PRIVATE_PROOF_REGISTRY = os.path.join(ROOT, "data", "ctf_benchmark",
                                     "private_pool_registry.json")
LEAK = os.path.join(ROOT, ".workbuddy", "tmp", "rev_leak.out")
ORCH = os.path.join(ROOT, "scripts", "ctf_stepfun_orchestrator.py")
WORKDIR = os.path.join(ROOT, ".workbuddy", "tmp", "capability_eval")
EVIDENCE_PATH = os.path.join(WORKDIR, "evidence.auto.json")
PRIOR_AUDIT = os.path.join(ROOT, "docs", "evidence", "capability_eval_20261105",
                           "pool_prior_audit.json")
PRIOR_AUDIT_V2 = os.path.join(ROOT, "docs", "evidence", "capability_eval_20261105",
                              "pool_prior_audit_v2.json")


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot_result(path):
    """跑批前给结果文件拍一份字节级快照（不存在也记录为快照，不算失败）。"""
    if not path or not os.path.isfile(path):
        return {"exists": False, "sha256": None, "mtime_ns": None}
    st = os.stat(path)
    return {"exists": True, "sha256": _sha256(path), "mtime_ns": st.st_mtime_ns}


def verify_run_result(result_path, snapshot, pool_path, rc, started_ns):
    """跑批后**结果级**绑定校验（纯函数，只读文件，便于变异验证）。

    2026-11-06 第十一个偏差：旧实现把命令里的 `--benchmark` 池指纹抄进
    `ev["result_pool_sha256"]` 就算「结果池绑定」，但那是**参数自证**——
    与结果文件内容毫无关系。实测两个攻击形态都能产出 verdict：
      · 跑批命令 rc=0 却根本不写结果文件 ⇒ 判分读的是上一次的旧结果；
      · 跑批命令 rc=7 明确失败 ⇒ rc 被忽略，照样判分。
    因此这里要求三件事同时成立，任一不满足即 fail-closed 拒绝判分：
      1. 命令 rc=0 且结果文件存在、可解析、details 非空；
      2. 结果文件确实被本次跑批重写（内容/mtime 未变 ⇒ 旧结果洗白）；
      3. 结果里的题 id 全部属于本批次题池（旧池结果不能套新池指纹）。
    """
    reasons = []
    if rc != 0:
        reasons.append("跑批命令 rc=%d ≠ 0（旧实现会忽略并继续判分）" % rc)
    if not result_path or not os.path.isfile(result_path):
        reasons.append("结果文件不存在：本次跑批未产出结果")
        return False, reasons

    after_sha = _sha256(result_path)
    try:
        st = os.stat(result_path)
    except OSError as exc:
        reasons.append("结果文件 stat 失败: %s" % exc)
        return False, reasons
    if snapshot.get("exists"):
        same_bytes = snapshot.get("sha256") == after_sha
        mtime_unchanged = st.st_mtime_ns <= (snapshot.get("mtime_ns") or 0)
        if same_bytes and mtime_unchanged:
            reasons.append("结果文件字节与 mtime 均未变 ⇒ 旧结果被当成本次批次（洗白）")
    if st.st_mtime_ns < started_ns:
        reasons.append("结果文件 mtime 早于本次跑批开始 ⇒ 未被本次跑批写入")

    try:
        with open(result_path, encoding="utf-8") as f:
            doc = json.load(f)
        details = doc.get("details") or []
    except Exception as exc:
        reasons.append("结果文件无法解析为 JSON: %s" % exc)
        return False, reasons
    if not details:
        reasons.append("结果文件 details 为空（空跑批次）")
    ids = {str(d.get("id", "")) for d in details if isinstance(d, dict)}
    questions, pool_ok = load_questions(pool_path)
    pool_ids = set(questions.keys())
    if not pool_ok or not pool_ids:
        reasons.append("本批次题池为空或读取失败")
    outside = sorted(ids - pool_ids)
    if outside:
        reasons.append("结果含 %d 道不属于本批次题池的题（疑似旧池结果）: %s"
                       % (len(outside), ", ".join(outside[:3])))
    return (not reasons), reasons


def scoring_gap_fragment(result_path):
    """判分「不去壳」假阴性片段：随 verdict 一起走，不靠外围文档提醒。

    只量化，不改判分、不重算分数。审计失败时 false_negative_count=None，
    报告层会明确警告，不得把该批次读数当成无偏差。
    """
    try:
        gap = audit_scoring_variant_gap.audit(result_path)
        return {
            "false_negative_count": gap["false_negative_count"],
            "false_negative_ids": gap["false_negative_ids"],
            "result_sha256": gap["result_sha256"],
            "note": ("只量化假阴性，不改判分、不重算分数；"
                     "verify_flag 位于他人 WIP orchestrator、candidate_variants 位于共享 flag_util，均未修"),
        }
    except Exception as exc:
        return {"false_negative_count": None, "error": str(exc),
                "note": "假阴性审计失败（fail-closed：不得把本批次读数当作无偏差）"}


# 题面引用的外部文件名（附件/工件）。只用于「结构可解性」标注，不参与判分。
_FILE_REF_RE = re.compile(
    r"\b[\w\-]+\.(?:py|txt|json|csv|pcap|png|jpg|bin|zip|enc|log|sage|c|cpp|go|js|wasm)\b",
    re.I)


def attachment_dependency_fragment(result_path, pool_path, command=None):
    """§19 结构可解性标注：题面引用外部文件，但 pure_llm 路径不给附件。

    2026-11-06 首次真实端到端跑批实证：v2 池前 3 题的 description 都写着
    「you are given two files: source.py, output.txt」，模型 3/3 明确回复
    「你未提供这两个文件的具体内容，缺少必要信息无法完成推导」，`got` 全空。
    全池 154 题里 17 题引用外部文件名，`_attachments` 下 0/17 有对应目录，
    且这 17 题与 23 道 `requires_airgap` 题零交集 ⇒ 标注维度没覆盖附件缺失。

    判据只认**代码级事实**：跑批命令是否提供 `--artifact-dir`。pure_llm 前置
    守卫本来就禁止该参数，所以此类题在此路径下不具备解题所需输入。
    不查附件目录（被 gitignore，CI checkout 里可能不存在，会造成假阴性）。

    **只量化标注**：不改判分、不重算 rate、不从分母剔除（题池指纹已钉死，
    剔题会让历史 verdict 的池绑定失效）。结论作用域仍是工程回归读数。
    """
    cmd = [x for x in (command or []) if x != "--"]
    supplied = "--artifact-dir" in cmd
    try:
        result = json.load(open(result_path, encoding="utf-8"))
        problems = json.load(open(pool_path, encoding="utf-8")).get("problems", {})
        ids = [d.get("id") for d in result.get("details", [])]
        bad = [i for i in ids
               if isinstance(problems.get(i), dict)
               and _FILE_REF_RE.search(str(problems[i].get("description") or ""))]
        return {
            "attachment_dependent_count": len(bad) if not supplied else 0,
            "attachment_dependent_ids": [] if supplied else bad,
            "artifact_dir_supplied": supplied,
            "batch_size": len(ids),
            "note": ("题面引用外部文件且本批次未提供 --artifact-dir ⇒ 该路径下"
                     "结构不可解；真实跑批 3/3 模型明确回复缺文件。只标注，"
                     "不改判分/不剔分母/不改题池（池指纹钉死）"),
        }
    except Exception as exc:
        return {"attachment_dependent_count": None,
                "artifact_dir_supplied": supplied, "error": str(exc),
                "note": "结构可解性审计失败（fail-closed：不得把本批次读数当作模型能力结论）"}


def attachment_dependency_selftest():
    """G 段：结构可解性标注变异验证（合成池/合成结果，非评测）。"""
    import tempfile

    tmp = tempfile.mkdtemp(prefix="wb_attdep_")
    cases = []
    try:
        pool_p = os.path.join(tmp, "pool.json")
        res_p = os.path.join(tmp, "result.json")
        json.dump({"problems": {
            "needs_file": {"description": "You are given two files: source.py and output.txt."},
            "self_contained": {"description": "Compute 2+2 and report the result."},
        }}, open(pool_p, "w", encoding="utf-8"))
        json.dump({"details": [{"id": "needs_file"}, {"id": "self_contained"},
                               {"id": "not_in_pool"}]},
                  open(res_p, "w", encoding="utf-8"))

        def case(label, cmd, want, pool=pool_p):
            frag = attachment_dependency_fragment(res_p, pool, cmd)
            got = frag.get("attachment_dependent_count")
            cases.append((label, got, want))

        case("未给附件 ⇒ 只标 1 题", ["python", "orch.py"], 1)
        case("带 --artifact-dir ⇒ 归零", ["python", "orch.py", "--artifact-dir", "d"], 0)
        case("池损坏 ⇒ fail-closed None", ["python", "orch.py"], None,
             pool=os.path.join(tmp, "missing.json"))
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    passed = 0
    for label, got, want in cases:
        good = got == want
        passed += int(good)
        print("  %s %-34s got=%s want=%s"
              % ("PASS" if good else "FAIL", label, got, want))
    print("结构可解性标注变异验证：%d/%d" % (passed, len(cases)))
    return passed == len(cases)


_FP_DEPS = ("gmpy2", "scapy", "brotli", "zstandard", "sympy", "fastapi", "pycryptodome")


def _run_capture(cmd, cwd):
    """跑一条命令拿 (rc, stdout, stderr)，任何异常都不抛。"""
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=20)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except Exception as exc:  # noqa: BLE001
        return -1, "", "%s: %s" % (type(exc).__name__, exc)


def _dep_versions(names):
    """关键依赖版本。**未安装记 None，不省略键** —— 省掉键等于把「缺依赖」这一
    事实从指纹里删掉，而缺依赖会改变结论（服务器实测：缺 scapy+brotli 时 pcap
    通道根本不存在，同一份代码跑出来的数不是同一件事）。"""
    out = {}
    try:
        from importlib import metadata
    except ImportError:  # pragma: no cover
        return out
    for n in names:
        try:
            out[n] = metadata.version(n)
        except Exception:  # noqa: BLE001
            out[n] = None
    return out


def code_fingerprint(root=None):
    """本次跑批所用代码的指纹：commit + 工作区脏度 + 解释器 + 关键依赖版本。

    为什么必须有（2026-11-08 实测）：服务器 `~/sam` 落后仓库 HEAD **37 个 commit /
    207 个文件**，服务器上另有 4 份无 git 的副本（`ctf_run`/`SecAutoMind`/
    `_p3_003_patch_ctfrun`/`sam_s1`），而历史结果文件里**没有一个字段**能区分
    「跑的是哪份代码」—— 88.3% 那批至今无法回溯到代码版本。
    这与「无指纹永不可归因」是同一个根：不是缺文档，是缺字段。

    三条刻意的设计：

      1. **脏工作区必须记出来，且不许当干净**。服务器工作区正是「落后 37 commit +
         手工粘贴的新文件」这种形态；只记 commit 会让指纹撒谎。所以
         `clean_checkout` 同时要求「有 commit」且「未提交改动数 == 0」。
      2. **解释器与依赖一起记**。同一份代码在缺 scapy 的机器上 pcap 通道不存在，
         跑出来的数不是同一件事。
      3. **任何一步失败都返回 available=False + 原因，不抛异常**。评测入口不能因为
         `git` 不在 PATH 就崩，但也绝不能因此假装自己有指纹（fail-closed 只关
         `clean_checkout` 这一个布尔，不是把错误吞掉）。
    """
    root = root or ROOT
    fp = {
        "root": root,
        "python": "%d.%d.%d" % tuple(sys.version_info[:3]),
        "implementation": getattr(sys.implementation, "name", ""),
        "commit": "",
        "branch": "",
        "dirty_files": -1,
        "dirty": None,
        "clean_checkout": False,
        "deps": {},
        "available": False,
        "error": "",
        "note": "",
    }
    rc, out, err = _run_capture(["git", "rev-parse", "HEAD"], root)
    if rc != 0 or not out:
        fp["error"] = "git 不可用或非仓库：%s" % (err or out)[:160]
        return fp
    fp["commit"] = out.splitlines()[0]
    rc2, out2, _ = _run_capture(["git", "rev-parse", "--abbrev-ref", "HEAD"], root)
    fp["branch"] = out2.splitlines()[0] if rc2 == 0 and out2 else ""
    rc3, out3, err3 = _run_capture(["git", "status", "--porcelain"], root)
    if rc3 != 0:
        fp["error"] = "git status 失败：%s" % err3[:160]
        fp["deps"] = _dep_versions(_FP_DEPS)
        return fp
    dirty_lines = [ln for ln in out3.splitlines() if ln.strip()]
    fp["dirty_files"] = len(dirty_lines)
    fp["dirty"] = bool(dirty_lines)
    fp["deps"] = _dep_versions(_FP_DEPS)
    fp["available"] = True
    fp["clean_checkout"] = not dirty_lines
    if dirty_lines:
        fp["note"] = ("工作区有 %d 个未提交改动 ⇒ 本次跑批**不能**等价于 commit %s"
                      % (len(dirty_lines), fp["commit"][:12]))
    return fp


def _fixed_temperature_proven(path=None):
    """请求体是否显式固定 temperature —— 用 AST 判，不看源码文字。

    实证（2026-11-08）：旧实现用正则 `["']temperature["']\\s*:\\s*([0-9.]+)` 扫
    orchestrator 源码。2026-11-07 为了按模型做条件发送（kimi 系列 400 不认
    temperature），请求体从 dict 字面量 `{"temperature": 0.2}` 改成下标赋值
    `payload["temperature"] = 0.2`。**行为一模一样，正则却从 2 命中掉到 0 命中**
    ⇒ preflight 判 `temperature_fixed=False`，而落盘 evidence 里还写着 `True`
    （那份是用旧代码生成的，此后从未重跑）。
    反方向同样成立：把 `{"temperature": 0.2}` 写进注释或字符串，旧正则会判 True，
    而真实请求体里根本没有这个字段。
    一个判据同时能出假红和假绿，说明它测的是**文字**而不是**行为**。

    修法：AST 层面数两件事，再交叉比对——
      · 请求体字面量:含 `"model"` 与 `"messages"` 两个 key 的 dict
        （实测两处:纯 LLM 请求 + 工具轮请求）；
      · temperature 覆盖:`<x>["temperature"] = <num>` 下标赋值 + dict 字面量里的
        `"temperature": <num>`。
    判据 = 覆盖数 >= 请求体数 且 取值唯一。新增一条请求路径却忘加 temperature、
    或把值改掉，都会红；只写在注释里不计入（AST 看不到注释）。
    """
    import ast

    target = path or ORCH
    if not os.path.isfile(target):
        return False, "orchestrator 不存在: %s" % target
    try:
        src = open(target, encoding="utf-8", errors="replace").read()
        tree = ast.parse(src)
    except (OSError, SyntaxError) as exc:
        # 解析不了就 fail-closed：判据失效不许当成「已验证」。
        return False, "orchestrator 不可读/不可解析:%s（判据失效 ⇒ fail-closed）" % exc

    def _num(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) \
                and not isinstance(node.value, bool):
            return float(node.value)
        return None

    def _is_const(node, want):
        return isinstance(node, ast.Constant) and node.value == want

    # ① 请求体字面量:同时含 "model" 与 "messages"
    req_dicts = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Dict):
            keys = {k.value for k in n.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)}
            if {"model", "messages"} <= keys:
                req_dicts.append(n)

    # ② temperature 覆盖:下标赋值 + dict 字面量
    covered = []          # (行号, 值, 是否条件发送)
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Subscript) and _is_const(t.slice, "temperature"):
                    v = _num(n.value)
                    if v is not None:
                        covered.append((n.lineno, v))
        elif isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values):
                if _is_const(k, "temperature"):
                    num = _num(v)
                    if num is not None:
                        covered.append((n.lineno, num))

    if not req_dicts:
        return False, "未找到任何请求体字面量（含 model+messages）——形状变化，判据失效（fail-closed）"
    if len(covered) < len(req_dicts):
        return False, ("请求体 %d 处，只固定了 %d 处 temperature（行 %s）"
                       "⇒ 存在未固定温度的请求路径"
                       % (len(req_dicts), len(covered),
                          ",".join(str(ln) for ln, _ in covered) or "无"))
    vals = sorted({v for _, v in covered})
    if len(vals) != 1:
        return False, "temperature 取值不唯一:%r（行 %s）" % (
            vals, ",".join(str(ln) for ln, _ in covered))
    return True, ("AST:请求体 %d 处全部显式固定 temperature=%s（%d 处赋值，行 %s；"
                  "条件发送见 `_accepts_temperature`：不支持该参数的模型不带此字段）"
                  % (len(req_dicts), _fmt_num(vals[0]), len(covered),
                     ",".join(str(ln) for ln, _ in covered)))


def _fmt_num(x):
    """0.2 而不是 0.20000000000000001。"""
    return ("%g" % x)


def claim_scope_for_pool(pool_path=POOL, audit_path=PRIOR_AUDIT, bound_pool_sha=None,
                         registry_path=PRIVATE_PROOF_REGISTRY):
    """题源先验 → 本批次「结论作用域」，代码重算、fail-closed。

    `claimable=True` 只说明链路合规、格式可引用；它**不代表**这个数值可以叫
    「能力率」。公开题池的命中数无法排除模型记忆 / 公开 writeup，只能作工程回归
    读数。本函数把这一区分写进 verdict，避免靠外围文档提醒（§13 三个假绿的教训）。

    作用域三值：
      capability_rate_candidate  —— 全部题目可证明私有、审计证据一致，且私有性有
                                    **外部锚点**（git 首次提交时间戳 + 内容指纹 +
                                    公开真值排除，见 audit_private_proof.py）
      engineering_regression_only—— 存在公开/来源不明题，或私有性仅靠题面自证
      unverified                 —— 题池或审计证据缺失/漂移/绑定指纹不一致，禁止引用

    §17 修正（第六个偏差）：`audit_pool_prior.classify()` 的四条私有判据全部取自
    题面字段。实测把 v2 的 154 道公开题只改 id/name/description/pool/source/
    created_at（flag_sha256 不动）就能得到 private_proven=154/154 并让本函数
    返回 capability_rate_candidate。故「题面自证」一律不作为放行依据。
    """
    scope = {
        "generated_by": "scripts/run_capability_eval.py::claim_scope_for_pool (代码重算)",
        "pool_path": os.path.relpath(pool_path, ROOT).replace("\\", "/"),
        "audit_evidence_path": os.path.relpath(audit_path, ROOT).replace("\\", "/"),
        "claim_scope": "unverified",
        "private_proven": 0,
        "total": 0,
        "pool_sha256": None,
        "bound_pool_matches": None,
        "audit_evidence_consistent": False,
        "private_proof_anchored": False,
        "private_proof_anchored_count": 0,
        "private_proof_reason": "",
        "private_proof_contract": audit_private_proof.CONTRACT,
        "private_proof_registry_path": os.path.relpath(
            registry_path, ROOT).replace("\\", "/"),
        "reason": "",
    }
    if not os.path.isfile(pool_path):
        scope["reason"] = "题池不存在，fail-closed"
        return scope
    # 私有性外部锚点：代码重算，fail-closed。异常也不许当成「已验证」。
    try:
        proof = audit_private_proof.assess(pool_path, registry_path,
                                           require_tracked=True)
    except Exception as exc:  # pragma: no cover - 环境异常必须降级而非崩溃
        proof = {"anchored": False, "anchored_count": 0,
                 "reasons": ["proof_assessment_error:%s" % type(exc).__name__]}
    scope.update({
        "private_proof_anchored": bool(proof["anchored"]),
        "private_proof_anchored_count": proof["anchored_count"],
        "private_proof_reason": "; ".join(proof["reasons"]) or "R0–R6 全过",
    })
    fresh = audit_pool_prior.audit(pool_path)
    scope.update({
        "pool_sha256": fresh["pool_sha256"],
        "private_proven": fresh["counts"]["private_proven"],
        "total": fresh["total"],
        "public_named": fresh["counts"]["public_named"],
        "requires_airgap": fresh["requires_airgap"],
        "prior_cutoff": fresh["prior_cutoff"],
        "capability_rate_publishable": fresh["capability_rate_publishable"],
    })
    # 池自带的结构性限制随 verdict 一起走，避免「结论边界只写在外围文档里」。
    try:
        scope["pool_known_limitations"] = list(
            json.load(open(pool_path, encoding="utf-8"))
            .get("provenance", {}).get("known_limitations", []))
    except Exception:
        scope["pool_known_limitations"] = []
    if bound_pool_sha and bound_pool_sha != fresh["pool_sha256"]:
        scope["bound_pool_matches"] = False
        scope["reason"] = "结果绑定的题池指纹与审计池不一致（防洗白）"
        return scope
    scope["bound_pool_matches"] = True if bound_pool_sha else None

    if not os.path.isfile(audit_path):
        scope["reason"] = "题源审计证据不存在；请先跑 audit_pool_prior.py"
        return scope
    try:
        saved = json.load(open(audit_path, encoding="utf-8"))
    except Exception as exc:
        scope["reason"] = "题源审计证据解析失败: %s" % exc
        return scope
    consistent = (saved.get("pool_sha256") == fresh["pool_sha256"]
                  and saved.get("counts") == fresh["counts"]
                  and saved.get("capability_rate_publishable")
                  == fresh["capability_rate_publishable"])
    scope["audit_evidence_consistent"] = consistent
    if not consistent:
        scope["reason"] = "题源审计证据与代码重算不一致（指纹/计数/结论漂移）"
        return scope

    # 题面自曝答案：现有明文门禁的空洞绿（只扫 word{} token 且不去壳），
    # 这里用 sha256 反查重算，逐题列出 id（不含任何明文答案）。
    try:
        probs = json.load(open(pool_path, encoding="utf-8")).get("problems", {})
        tainted = sorted(pid for pid, p in probs.items()
                          if isinstance(p, dict)
                          and audit_writeup_answer.inspect_problem(pid, p))
        scope["statement_tainted_count"] = len(tainted)
        scope["statement_tainted_ids"] = tainted
    except Exception as exc:
        scope["statement_tainted_count"] = None
        scope["statement_tainted_ids"] = []
        scope["statement_tainted_error"] = str(exc)

    if fresh["total"] > 0 and fresh["counts"]["private_proven"] == fresh["total"]:
        if scope["private_proof_anchored"]:
            scope["claim_scope"] = "capability_rate_candidate"
            scope["reason"] = ("全池题目可证明私有且私有性有外部锚点；"
                               "仍须逐题满足其余判据")
        else:
            # §17：题面自证全私有 ≠ 题目私有。不给锚点就不采信。
            scope["claim_scope"] = "engineering_regression_only"
            scope["reason"] = ("题面自证全私有但缺外部锚点（%s）⇒ 不采信，"
                               "数值只能作工程回归读数" % scope["private_proof_reason"])
    else:
        scope["claim_scope"] = "engineering_regression_only"
        scope["reason"] = "%d/%d 题公开或来源不明 ⇒ 模型先验无法排除，数值只能作工程回归读数" % (
            fresh["total"] - fresh["counts"]["private_proven"], fresh["total"])
    if scope.get("statement_tainted_count"):
        scope["reason"] += "；且分母含 %d 道题面自曝答案题，工程回归读数亦须打折" % \
                           scope["statement_tainted_count"]
    return scope


def agentic_run_binding(proof, command):
    """已抽到共享模块 scripts/agentic_binding.py（§18 唯一口径）。

    这里保留同名薄封装：本文件内的 preflight / selftest 与既有引用不改一行，
    判据实现只在 agentic_binding.py 维护，杜绝两份口径漂移。
    """
    from agentic_binding import agentic_run_binding as _impl
    return _impl(proof, command)


def airgap_scope_selftest():
    """F 段：agentic 跨层绑定变异验证（合成证据，不调 LLM、不产出分数）。"""
    import copy

    cmd = ["python", "scripts/ctf_stepfun_orchestrator.py", "--agentic",
           "--benchmark", "pool.json"]
    fp = hashlib.sha256(" ".join(cmd).encode("utf-8")).hexdigest()
    good = {
        "ip_direct_blocked": True, "af_unix_ok": True,
        "run_binding": {"command_sha256": fp,
                         "subprocess_ip_direct_blocked": True},
    }
    cases = []

    def case(label, proof, command, want):
        got, why = agentic_run_binding(proof, command)
        cases.append((label, got, want, why))

    case("无证据 ⇒ 拒绝", {}, cmd, False)
    case("机制 A/B 不成立 ⇒ 拒绝",
         {**good, "ip_direct_blocked": False}, cmd, False)
    case("只有机制证据、无跑批命令 ⇒ 拒绝", good, [], False)
    p = copy.deepcopy(good)
    p.pop("run_binding")
    case("有跑批命令但缺 run_binding ⇒ 拒绝", p, cmd, False)
    case("命令指纹不匹配 ⇒ 拒绝",
         {**good, "run_binding": {**good["run_binding"], "command_sha256": "0" * 64}},
         cmd, False)
    case("子进程未证明拦截 ⇒ 拒绝",
         {**good, "run_binding": {**good["run_binding"],
                                 "subprocess_ip_direct_blocked": False}}, cmd, False)
    case("双条件齐备 ⇒ 放行", good, cmd, True)

    passed = 0
    for label, got, want, why in cases:
        good_case = got is want
        passed += int(good_case)
        print("  %s %-36s got=%s want=%s %s"
              % ("PASS" if good_case else "FAIL", label, got, want,
                 "" if good_case else why[:70]))
    print("agentic 跨层绑定变异验证：%d/%d" % (passed, len(cases)))
    return passed == len(cases)


def preflight(args):
    """真实检查，不模拟、不伪造。返回 (ok, checks, evidence)。

    §13 修正：Go runner 的三个开关与 IP 直连 proof 只在 **agentic 路径**
    （有 python_session 解题子进程）才适用。pure_llm 路径模型没有代码执行
    出口，这些开关在 orchestrator 里全树无消费者 ⇒ 标 N/A，不参与放行判定，
    改由判分时用 prove_pure_llm_path() 从结果+源码自动生成内生证据。
    """
    checks = []
    mode = args.mode

    # 代码指纹先算一次，供 chk 与 evidence 共用同一个值（避免两次调用拿到不一致状态，
    # 例如中间有人改了文件）。
    # warn=True 的理由：脏工作区在开发中很常见，一票否决会让评测入口不可用；但
    # 它必须**可见**并且写进 evidence —— 只记 commit 的指纹会撒谎。
    cfp = code_fingerprint()
    _deps_brief = ",".join("%s=%s" % (k, v if v else "MISS")
                           for k, v in (cfp.get("deps") or {}).items())

    def chk(name, ok, note, na=False, warn=False):
        checks.append({"item": name, "ok": bool(ok), "note": str(note),
                       "na": bool(na), "warn": bool(warn)})

    na_note = ("N/A：该开关的消费者全在 Go 侧（cmd/llmbench / cmd/runner / internal/airgap "
               "/ py_session.go），ctf_stepfun_orchestrator.py 无消费者；设了也不证明本路径任何性质")
    if mode == "agentic":
        chk("CTF_AIRGAP=1", os.environ.get("CTF_AIRGAP") == "1",
            "env CTF_AIRGAP=%r" % os.environ.get("CTF_AIRGAP"))
        chk("RUNNER_LLM_NO_FALLBACK=1", os.environ.get("RUNNER_LLM_NO_FALLBACK") == "1",
            "env RUNNER_LLM_NO_FALLBACK=%r" % os.environ.get("RUNNER_LLM_NO_FALLBACK"))
        chk("CTF_AGENT_INTERNAL_PRESOLVE=off",
            os.environ.get("CTF_AGENT_INTERNAL_PRESOLVE") == "off",
            "env CTF_AGENT_INTERNAL_PRESOLVE=%r" % os.environ.get("CTF_AGENT_INTERNAL_PRESOLVE"))
    else:
        chk("CTF_AIRGAP=1", True, na_note, na=True)
        chk("RUNNER_LLM_NO_FALLBACK=1", True, na_note, na=True)
        chk("CTF_AGENT_INTERNAL_PRESOLVE=off", True, na_note, na=True)

    proof = {}
    proof_ok = False
    bound_ok, bound_note = False, "N/A：pure_llm 路径无解题子进程"
    if args.airgap_proof and os.path.isfile(args.airgap_proof):
        try:
            proof = json.load(open(args.airgap_proof, encoding="utf-8"))
            proof_ok = proof.get("ip_direct_blocked") is True and proof.get("af_unix_ok") is True
        except Exception as exc:
            proof = {"parse_error": str(exc)}
    if mode == "agentic":
        chk("airgap IP 直连证据（机制层）", proof_ok,
            "需 ip_direct_blocked=true 且 af_unix_ok=true；实得 %s" % json.dumps(proof, ensure_ascii=False)[:180])
        # §18：机制层 proof 的作用域是 Go 探测二进制。必须再证明「本次跑批的
        # 解题子进程」被隔离，否则上一轮那种「前置全绿但 Python 子进程可出网」
        # 的跨层假绿会重演。当前证据无 run_binding ⇒ 恒拒（fail-closed）。
        bound_ok, bound_note = agentic_run_binding(proof, [x for x in args.command if x != "--"])
        chk("本次跑批解题子进程隔离绑定", bound_ok, bound_note)
    else:
        chk("airgap IP 直连证据（机制层）", True,
            "N/A：pure_llm 无解题子进程，seccomp 拦的是 Go 侧 python_session", na=True)
        proof_ok = True

    pool_path, manifest_path = args.pool, args.manifest
    pool_ok, pool_sha = False, ""
    if os.path.isfile(pool_path) and os.path.isfile(manifest_path):
        mf = json.load(open(manifest_path, encoding="utf-8"))
        pool_sha = _sha256(pool_path)
        pool_ok = pool_sha == mf.get("out_sha256")
    chk("题池指纹与 manifest 一致", pool_ok,
        "pool=%s actual=%s" % (os.path.basename(pool_path), pool_sha[:16]))

    rows = analyze(ROOT)
    scanned = any(r["file"] == os.path.basename(pool_path) for r in rows)
    gate_ok = scanned and not violations(rows)
    chk("明文答案门禁覆盖新池且零违规", gate_ok,
        "扫到 %d 集，新池在扫描内=%s，violations=%d" % (len(rows), scanned, len(violations(rows))))

    # 守卫 A：本批次题池「自然语言自曝答案」必须为 0，由代码逐题重算。
    # 明文门禁对 v1 的 6 题因登记基线放行（CI 不常红），但**评测入口不接受
    # v1 起新跑批** —— 这才是真正拦住历史脏池的锁，而不是一句文档提醒。
    tainted, sd_error = -1, ""
    try:
        sel_probs = json.load(open(pool_path, encoding="utf-8")).get("problems", {})
        tainted = sum(1 for p in sel_probs.values()
                      if isinstance(p, dict) and self_disclosure_in_statement(p))
    except Exception as exc:
        sd_error = str(exc)
    chk("本批次题池无题面自曝答案（代码重算）", tainted == 0,
        "tainted=%d %s；v1=6 应被拒，v2=0 才放行" % (tainted, sd_error))

    # 守卫 B：--run 时命令里实际使用的 --benchmark 必须与 --pool 同指纹。
    # 否则「用 v2 过前置、命令却指向 v1」会把脏池结果洗白。
    cmd_args = [x for x in args.command if x != "--"]
    bench = None
    for i, x in enumerate(cmd_args):
        if x == "--benchmark" and i + 1 < len(cmd_args):
            bench = cmd_args[i + 1]
            break
    if cmd_args:
        bp = bench and (bench if os.path.isabs(bench) else os.path.join(ROOT, bench))
        bench_sha = _sha256(bp) if bp and os.path.isfile(bp) else None
        chk("跑批命令题池与 --pool 同指纹（防洗白）",
            bench_sha is not None and bench_sha == pool_sha,
            "cmd_benchmark=%s cmd_sha=%s pool_sha=%s"
            % (bench, str(bench_sha)[:16], pool_sha[:16]))
    else:
        chk("跑批命令题池与 --pool 同指纹（防洗白）", True,
            "N/A：--preflight/--adjudicate 无跑批命令；--run 时强制校验", na=True)

    temp_ok, temp_note = _fixed_temperature_proven()
    chk("随机源代码级固定", temp_ok, temp_note)

    if mode == "pure_llm":
        try:
            osrc = open(ORCH, encoding="utf-8", errors="replace").read()
        except Exception:
            osrc = ""
        shape_ok = (re.search(r"if\s+agentic\s+and\s+cfg\.get\(\s*[\"']supports_tools[\"']\s*\)", osrc) is not None
                    and re.search(r'["\']tool_calls["\']\s*:\s*0', osrc) is not None
                    and "run_python_tool(" in osrc)
        chk("源码：非 agentic 分支写死 tool_calls=0 且工具受门控", shape_ok,
            "orchestrator 源码正则形状（完整 AST 证明在判分时由 prove_pure_llm_path 补齐）")
        cmd_args = [x for x in args.command if x != "--"]
        cmd_ok = not cmd_args or ("--agentic" not in cmd_args and "--artifact-dir" not in cmd_args)
        chk("跑批命令未启用 --agentic / --artifact-dir", cmd_ok,
            "command=%r" % " ".join(cmd_args)[:150])

    # 题池入库状态：必须真的出现在 git 历史里（clone 下来的评委能拿到题）。
    # 只用 git ls-files 会把「git add 后未 commit」也算成入库 —— 那是第三个假绿。
    tracked = False
    try:
        r = subprocess.run(["git", "log", "-1", "--format=%H", "--",
                            os.path.relpath(pool_path, ROOT).replace("\\", "/")],
                           cwd=ROOT, capture_output=True, text=True, timeout=10)
        tracked = r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        tracked = False
    chk("题池已纳入 git 历史（对外可引用性）", tracked,
        "in_history=%s；须显式 git add -f 且 commit，仅 staged 不算" % tracked,
        warn=True)
    pool_tracked = tracked

    # 代码指纹：不阻断（脏树在开发中常见），但必须可见 + 写进 evidence。
    # `available=False` 时也要报，且 note 说明原因 —— 不能因为 git 不可用就静默跳过
    # 这一条，否则「没有指纹」会看起来像「指纹合格」。
    chk("代码指纹（commit + 工作区脏度 + 依赖）",
        cfp.get("clean_checkout") is True,
        ("commit=%s branch=%s dirty=%s python=%s deps[%s]%s"
         % (cfp.get("commit") or "N/A", cfp.get("branch") or "N/A",
            cfp.get("dirty_files"), cfp.get("python"), _deps_brief,
            ("；" + cfp["note"]) if cfp.get("note") else
            ("；" + cfp["error"]) if cfp.get("error") else "")),
        warn=True)

    ok = all(c["ok"] for c in checks if not c.get("na") and not c.get("warn"))
    ev = {
        "run_id": "capability_eval_%s" % datetime.datetime.now().strftime("%Y%m%dT%H%M%S"),
        "generated_by": "scripts/run_capability_eval.py (自动生成，非人工填写)",
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "eval_path": mode,
        "evidence_contract": [k for k, _ in evidence_keys({"eval_path": mode})],
        "temperature_fixed": temp_ok,
        "temperature_basis": temp_note,
        # pool_tracked_and_clean 由判据按下面三个子键重算，这里不自行发绿。
        "pool_fingerprint_ok": pool_ok,
        "pool_gate_ok": gate_ok,
        "pool_sha256": pool_sha,
        "pool_path": os.path.relpath(pool_path, ROOT).replace("\\", "/"),
        "statement_tainted_in_selected_pool": tainted,
        "pool_in_version_control": pool_tracked,
        # 跑批代码的指纹。历史结果文件缺这个字段 ⇒ 那批数字无法回溯到代码版本
        # （服务器实测落后 HEAD 37 commit / 207 文件，且有 4 份无 git 副本）。
        # 只在 evidence 里记、不在 verdict 里用就成了死数据；judge_run 会把整个
        # evidence 原样带进 verdict（verdict["evidence"]["code_fingerprint"]），
        # 所以「结果 → 代码版本」这条链从这一版起才真正通。
        "code_fingerprint": cfp,
        "caveats": [
            "pool_tracked_and_clean 只证明「指纹一致+门禁覆盖」，不等于题池入库；对外引用前须入库",
            "temperature 显式固定 ≠ 逐位可复现；provider 采样与版本仍会带来方差",
            "pure_llm 无工具出口 ≠ 无先验知识，模型记忆与公开 writeup 无法由本链路排除",
            "code_fingerprint.clean_checkout=false 时，本次数值不能等价于该 commit；"
            "deps 里任一值为 null 表示该依赖未安装（缺依赖会改变结论，不只是少条通道）",
        ],
        "preflight_passed": ok,
        "_usage": "preflight_passed=false 时本证据只能用于「把历史批次判为不可归因」，禁止用于放行任何新跑批",
        "preflight_checks": checks,
    }
    if mode == "agentic":
        ev.update({
            "airgap_active": os.environ.get("CTF_AIRGAP") == "1",
            # §18：判据层读的就是这个键。只给机制层 proof 就写 True 会让
            # judge_one 把未隔离子进程的命中也归因成解出 ⇒ 必须与绑定同为 True。
            "airgap_zero_egress_proven": proof_ok and bound_ok,
            "airgap_scope": "解题子进程 python_session/skill/流式shell；LLM API 通道不在隔离范围（否则无法调用模型）",
            "airgap_scope_binding": {"proven": bound_ok, "reason": bound_note},
            "airgap_proof": proof,
            "no_fallback_proven": os.environ.get("RUNNER_LLM_NO_FALLBACK") == "1",
            "channel_attribution_proven": os.environ.get("RUNNER_LLM_NO_FALLBACK") == "1",
            "channel_basis": "入口固定单一 --provider；Python orchestrator 不走 Go 侧 fallback 链",
            "presolve_off_proven": os.environ.get("CTF_AGENT_INTERNAL_PRESOLVE") == "off",
        })
    else:
        # 不写 agentic 键，避免证据里出现「零外网已证明=True」这种与路径无关的假信号。
        ev["not_applicable_switches"] = {
            "CTF_AIRGAP / RUNNER_LLM_NO_FALLBACK / CTF_AGENT_INTERNAL_PRESOLVE / IP直连proof":
                "消费者全在 Go 侧（cmd/llmbench/cmd/runner/internal/airgap/py_session.go），"
                "pure_llm 路径无解题子进程；改用 prove_pure_llm_path 的结果+源码内生证据",
        }
        ev["_pending"] = "结果级内生证据在 --adjudicate 时自动生成并覆盖本证据"
    return ok, checks, ev


def adjudicate(result_path, ev, out_path, mode="pure_llm", command=None,
               auto_prove=True, pool=POOL, prior_audit=PRIOR_AUDIT,
               registry=PRIVATE_PROOF_REGISTRY):
    result = json.load(open(result_path, encoding="utf-8"))
    os.makedirs(WORKDIR, exist_ok=True)
    if mode == "pure_llm" and auto_prove:
        # 跑完再验：结果里只要出现任何 tool_calls != 0 / audit 非空，
        # 自动证明立刻把 no_model_egress_proven 置 False → 整批不可归因。
        frag, proof = prove_pure_llm_path(result, ORCH, command)
        merged = dict(ev)
        merged.update(frag)
        merged["caveats"] = list(ev.get("caveats", [])) + list(frag.get("caveats", []))
        ev = merged
        proof_path = os.path.join(WORKDIR, "%s.proof.json" % ev.get("run_id", "run"))
        with open(proof_path, "w", encoding="utf-8") as f:
            json.dump(proof, f, ensure_ascii=False, indent=2)
        ev["proof_report_path"] = os.path.relpath(proof_path, ROOT).replace("\\", "/")
    questions, _ = load_questions(pool)
    leak_ids, leak_ok = load_leak_ids(LEAK)
    trained, trained_ok = load_trained_ids(ROOT)
    v = judge_run(result, questions, ev, leak_ids, leak_ok, trained, trained_ok)
    # 结论作用域由代码重算，不读人工声明；绑定指纹不一致直接 fail-closed。
    v["claim_scope"] = claim_scope_for_pool(pool_path=pool, audit_path=prior_audit,
                                             bound_pool_sha=ev.get("result_pool_sha256"),
                                             registry_path=registry)
    v["scoring_variant_gap"] = scoring_gap_fragment(result_path)
    # §19：只标注结构不可解题，不改判分/不重算 rate/不剔分母。
    v["attachment_dependency"] = attachment_dependency_fragment(result_path, pool, command)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(v, f, ensure_ascii=False, indent=2)
    return v


def runbind_selftest():
    """--run 结果级绑定的变异验证（合成文件，不调 LLM、不产出分数）。"""
    import shutil
    import tempfile

    tmpdir = tempfile.mkdtemp(prefix="wb_runbind_")
    cases = []
    try:
        pool_p = os.path.join(tmpdir, "pool.json")
        res_p = os.path.join(tmpdir, "result.json")
        with open(pool_p, "w", encoding="utf-8") as f:
            json.dump({"problems": {
                "p1": {"id": "p1", "description": "合成题"},
                "p2": {"id": "p2", "description": "合成题"},
            }}, f)

        def write(ids):
            with open(res_p, "w", encoding="utf-8") as f:
                json.dump({"details": [
                    {"id": i, "solved": False, "latency": 1.0, "error": ""}
                    for i in ids]}, f)

        # 正向：首次跑批，结果文件原本不存在，本次写出。
        if os.path.isfile(res_p):
            os.remove(res_p)
        snap = snapshot_result(res_p)
        write(["p1", "p2"])
        ok, why = verify_run_result(res_p, snap, pool_p, 0, 1)
        cases.append(("首次跑批正常产出结果", ok, True, why))

        # 攻击 1：命令失败，但旧结果仍在 ⇒ 必须拒绝（旧实现忽略 rc）。
        ok, why = verify_run_result(res_p, snap, pool_p, 7, 1)
        cases.append(("跑批命令 rc=7", ok, False, why))

        # 攻击 2：结果文件字节与 mtime 都没变 ⇒ 旧结果洗白。
        snap_old = snapshot_result(res_p)
        ok, why = verify_run_result(res_p, snap_old, pool_p, 0, 1)
        cases.append(("结果文件未被本次跑批重写", ok, False, why))

        # 攻击 3：文件存在但 mtime 早于跑批开始 ⇒ 未被本次写入。
        ok, why = verify_run_result(
            res_p, {"exists": False, "sha256": None, "mtime_ns": None},
            pool_p, 0, 10 ** 20)
        cases.append(("结果 mtime 早于本次跑批开始", ok, False, why))

        # 攻击 4：旧池结果套新池指纹（题 id 不在本批次池内）。
        write(["zz_other_pool"])
        ok, why = verify_run_result(
            res_p, {"exists": False, "sha256": None, "mtime_ns": None},
            pool_p, 0, 1)
        cases.append(("结果含非本批次池的题", ok, False, why))

        # 正向：内容确实变化、题 id 全在池内 ⇒ 允许判分。
        write(["p1"])
        ok, why = verify_run_result(
            res_p, {"exists": True, "sha256": "0" * 64, "mtime_ns": 1},
            pool_p, 0, 1)
        cases.append(("重写结果且题全在本批次池内", ok, True, why))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    passed = 0
    for label, got, want, why in cases:
        good = got is want
        passed += int(good)
        print("  %s %-38s got=%s want=%s %s"
              % ("PASS" if good else "FAIL", label, got, want,
                 "" if good else str(why[:1])[:76]))
    print("--run 结果级绑定变异验证：%d/%d" % (passed, len(cases)))
    return passed == len(cases)


def _registry_threaded_proven():
    """源码级不变量：所有 adjudicate(...) 调用都必须显式透传 registry。

    实证（2026-11-07 扩池 40 题）：`--registry` 只接进了 `--adjudicate` 与
    `--annotate` 两条路径，`--run` 路径漏了。后果不是报错，而是那一次 40 题
    跑批（注册表 40/40 全锚定、且注册表在跑批前就已入库）被判成
    `engineering_regression_only`，日志只留一句 registry_pool_sha256_mismatch。
    参数漏接会**静默降级结论作用域**，所以这里用源码形状把它顶回来 ——
    加一个调用点忘了透传，CI 就红。
    """
    path = os.path.join(ROOT, "scripts", "run_capability_eval.py")
    try:
        src = open(path, encoding="utf-8").read()
    except OSError as exc:
        return False, "源码不可读: %s" % exc
    import ast
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        return False, "源码不可解析: %s（判据失效 ⇒ fail-closed）" % exc
    # 用 AST 而不是正则：字符串/注释里出现 adjudicate( 会误判（实测 3 例假阳性），
    # 而漏掉一个真实调用点就等于这条不变量失效。
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == "adjudicate"]
    if not calls:
        return False, "未找到任何 adjudicate 调用（形状变化 ⇒ 判据失效，fail-closed）"
    bad = [n for n in calls
           if not any(k.arg == "registry" for k in n.keywords)]
    return (not bad), ("%d 个调用点，缺 registry= 的 %d 个%s"
                       % (len(calls), len(bad),
                          "" if not bad else
                          "（行 %s）" % ",".join(str(n.lineno) for n in bad)))


def temperature_selftest():
    """合成源码验证 temperature 判据：能判真、能判假、且**不被注释骗**。

    最后一个变体是核心对照 —— `comment_only` 里的请求体没有任何 temperature，
    但注释中留着 `{"temperature": 0.2}`。旧正则看到它会判 True（假绿），
    AST 判据判 False。同一段合成源码上同时跑两种判据，把「测文字 vs 测行为」
    的差别钉死在自测里，而不是靠文档提醒。
    """
    os.makedirs(WORKDIR, exist_ok=True)

    good = (
        'def call_llm(model):\n'
        '    payload = {"model": model, "messages": [], "stream": False}\n'
        '    if ok(model):\n'
        '        payload["temperature"] = 0.2\n'
        '    return payload\n'
        '\n'
        'def call_tools(model):\n'
        '    payload = {"model": model, "messages": []}\n'
        '    if ok(model):\n'
        '        payload["temperature"] = 0.2\n'
        '    return payload\n'
    )
    drop_one = (
        'def call_llm(model):\n'
        '    payload = {"model": model, "messages": [], "stream": False}\n'
        '    if ok(model):\n'
        '        payload["temperature"] = 0.2\n'
        '    return payload\n'
        '\n'
        'def call_tools(model):\n'
        '    payload = {"model": model, "messages": []}\n'
        '    return payload\n'
    )
    # 显式写全，不用 str.replace 构造变体 —— 实测 replace 会因换行数不对而静默
    # 不生效，变体没变却"通过"，等于自测在空转。
    mixed = (
        'def call_llm(model):\n'
        '    payload = {"model": model, "messages": [], "stream": False}\n'
        '    if ok(model):\n'
        '        payload["temperature"] = 0.2\n'
        '    return payload\n'
        '\n'
        'def call_tools(model):\n'
        '    payload = {"model": model, "messages": []}\n'
        '    if ok(model):\n'
        '        payload["temperature"] = 0.9\n'
        '    return payload\n'
    )
    comment_only = (
        'def call_llm(model):\n'
        '    # 曾经这么写过：{"temperature": 0.2}\n'
        '    payload = {"model": model, "messages": [], "stream": False}\n'
        '    return payload\n'
        '\n'
        'def call_tools(model):\n'
        '    # payload["temperature"] = 0.2\n'
        '    payload = {"model": model, "messages": []}\n'
        '    return payload\n'
    )
    broken = 'def f(model):\n    payload = {"model": model, "messages": []\n'
    no_req = 'def f(x):\n    payload = {"a": 1}\n    return payload\n'

    cases = [
        ("baseline_two_paths", good, True),
        ("missing_one_path", drop_one, False),
        ("mixed_values", mixed, False),
        ("comment_only", comment_only, False),
        ("syntax_broken", broken, False),
        ("no_request_dict", no_req, False),
    ]
    passed = 0
    for name, src, want in cases:
        path = os.path.join(WORKDIR, "_temp_selftest_%s.py" % name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(src)
        try:
            got, note = _fixed_temperature_proven(path)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
        ok = got == want
        passed += int(ok)
        print("  %s %-20s got=%-5s want=%-5s %s"
              % ("PASS" if ok else "FAIL", name, got, want, note[:110]))

    # 核心对照：comment_only 上旧正则的结论（应为 True = 假绿）
    old = re.findall(r'["\']temperature["\']\s*:\s*([0-9.]+)', comment_only)
    old_says = bool(old)
    ctl = old_says is True
    passed += int(ctl)
    print("  %s %-20s 旧正则看到注释里的 %r ⇒ 会判 True（假绿实证）"
          % ("PASS" if ctl else "FAIL", "old_regex_fooled", old))

    print("temperature 判据变异验证：%d/%d" % (passed, len(cases) + 1))
    return passed == len(cases) + 1


def code_fingerprint_selftest():
    """合成仓库验证代码指纹判据：干净 / 脏 / 非仓库 / 依赖键完整。

    每条都对应一个真实会犯的错：
      · 干净仓库必须判 True —— 否则判据把正常情况也拦了，久了就被当噪音忽略；
      · **加一个未跟踪文件必须变脏** —— 服务器工作区正是「旧 commit + 手工粘贴的
        新文件」，只记 commit 的指纹会撒谎，这是本判据存在的全部理由；
      · 非 git 目录必须 available=False 且**带原因**，不许静默当成有指纹；
      · deps 必须每个键都在（未装为 None）—— 省掉键等于把「缺依赖」从指纹里删掉。
    """
    import tempfile

    cases = []
    tmprepo = tempfile.mkdtemp(prefix="_cfp_selftest_repo_")
    tmpnogit = tempfile.mkdtemp(prefix="_cfp_selftest_nogit_")
    gitbase = ["git", "-c", "user.name=selftest",
               "-c", "user.email=selftest@example.invalid"]
    try:
        rc, _, err = _run_capture(gitbase + ["init", "-q"], tmprepo)
        if rc != 0:
            print("  [i] git 不可用，本段跳过（%s）" % (err or "unknown")[:100])
            return True
        with open(os.path.join(tmprepo, "a.txt"), "w", encoding="utf-8") as f:
            f.write("a\n")
        _run_capture(gitbase + ["add", "a.txt"], tmprepo)
        rc, _, err = _run_capture(gitbase + ["commit", "-q", "-m", "init"], tmprepo)
        if rc != 0:
            print("  [i] 合成仓库无法 commit，本段跳过（%s）" % (err or "unknown")[:100])
            return True

        fp = code_fingerprint(tmprepo)
        cases.append(("clean_repo", fp.get("clean_checkout") is True,
                      "commit=%s dirty=%s err=%s"
                      % (fp.get("commit", "")[:8], fp.get("dirty_files"),
                         fp.get("error", ""))))

        with open(os.path.join(tmprepo, "b_untracked.txt"), "w", encoding="utf-8") as f:
            f.write("b\n")
        fp2 = code_fingerprint(tmprepo)
        cases.append(("untracked_flips_dirty",
                      fp2.get("clean_checkout") is False and fp2.get("dirty_files") == 1,
                      "dirty=%s note=%s"
                      % (fp2.get("dirty_files"), fp2.get("note", "")[:80])))

        fp3 = code_fingerprint(tmpnogit)
        cases.append(("non_git_is_unavailable",
                      fp3.get("available") is False and bool(fp3.get("error")),
                      "available=%s error=%s"
                      % (fp3.get("available"), fp3.get("error", "")[:80])))

        deps = (fp.get("deps") or {})
        cases.append(("deps_keys_complete",
                      set(deps) == set(_FP_DEPS),
                      "缺失键=%s" % (set(_FP_DEPS) - set(deps))))
    finally:
        import shutil
        for d in (tmprepo, tmpnogit):
            shutil.rmtree(d, ignore_errors=True)

    passed = 0
    for name, ok, detail in cases:
        passed += int(ok)
        print("  %s %-24s %s" % ("PASS" if ok else "FAIL", name, detail))
    print("代码指纹判据变异验证：%d/%d" % (passed, len(cases)))
    return passed == len(cases) and bool(cases)


def pipeline_selftest():
    """链路自测：判据层 + 入口层都能在合规条件下给出正向结论。

    明确边界：这里用**合成数据**验证代码路径，不是评测结果，不产出可引用分数。
    """
    print("=== A. 判据层变异验证 ===")
    rc = selftest()
    print("=== B. 入口层正向链路（合成数据，非评测）===")
    questions, _ = load_questions(POOL)
    ids = [k for k, v in questions.items() if not v.get("requires_airgap")][:2]
    ev = {k: True for k, _ in PURE_LLM_EVIDENCE_KEYS}
    ev["eval_path"] = "pure_llm"
    ev["pool_sha256"] = "f" * 64
    ev["result_pool_sha256"] = "f" * 64
    ev.update({"pool_fingerprint_ok": True, "pool_gate_ok": True,
               "pool_in_version_control": True})
    result = {"details": [
        {"id": ids[0], "solved": True, "hit_mode": "exact", "latency": 10.0, "error": ""},
        {"id": ids[1], "solved": False, "hit_mode": "", "latency": 11.0, "error": ""},
    ]}
    leak, leak_ok = load_leak_ids(LEAK)
    if not leak_ok:
        # 自测必须自包含：真实泄漏集在未入库的本机产物 .workbuddy/tmp/rev_leak.out，
        # CI checkout 拿不到。B 段验证的是「合规条件下代码能否给出正向结论」，
        # 用一份可用但为空的合成泄漏集即可；生产判分 adjudicate() 仍读真实泄漏集，
        # 缺失由 A 段变异用例「泄漏集不可用 => fail-closed」守住，两者不混淆。
        leak, leak_ok = set(), True
        print("  [i] 真实泄漏集不可用，B 段改用合成空泄漏集（生产判分仍 fail-closed）")
    trained, trained_ok = load_trained_ids(ROOT)
    v = judge_run(result, questions, ev, leak, leak_ok, trained, trained_ok)
    want = {"LLM_SOLVED": 1, "CLEAN_FAIL": 1, "NOT_ATTRIBUTABLE": 0}
    ok = (v["verdicts"] == want and v["capability_rate"] == 0.5 and v["claimable"])
    print("  %s 合成 2 题：verdicts=%s rate=%s claimable=%s（期望 %s / 0.5 / True）"
          % ("PASS" if ok else "FAIL", v["verdicts"], v["capability_rate"], v["claimable"], want))
    print("=== C. 结论作用域（题源先验）变异验证 ===")
    scope_rc = scope_selftest()
    print("=== D. 判分假阴性接线（合成结果，非评测）===")
    os.makedirs(WORKDIR, exist_ok=True)
    gap_path = os.path.join(WORKDIR, "_gap_selftest.result.json")
    secret = "zz_gap_selftest_0001"
    with open(gap_path, "w", encoding="utf-8") as f:
        json.dump({"details": [{
            "id": "g1", "solved": False, "got": "flag{%s}" % secret,
            "expected_sha256": hashlib.sha256(secret.encode()).hexdigest(),
            "raw_head": "",
        }]}, f)
    frag = scoring_gap_fragment(gap_path)
    gap_ok = frag.get("false_negative_count") == 1
    print("  %s 合成 1 题：false_negative_count=%s（期望 1）"
          % ("PASS" if gap_ok else "FAIL", frag.get("false_negative_count")))
    os.remove(gap_path)
    print("=== E. --run 结果级绑定变异验证（合成，非评测）===")
    runbind_ok = runbind_selftest()
    print("=== F. agentic 跨层作用域绑定变异验证（合成，非评测）===")
    airgap_scope_ok = airgap_scope_selftest()
    print("=== G. 结构可解性标注变异验证（合成，非评测）===")
    attdep_ok = attachment_dependency_selftest()
    print("=== H. 参数透传不变量（源码形状，非评测）===")
    reg_ok, reg_why = _registry_threaded_proven()
    print("  %s adjudicate 调用全部透传 registry（%s）"
          % ("PASS" if reg_ok else "FAIL", reg_why))
    print("=== I. temperature 判据（AST，合成源码）===")
    temp_ok = temperature_selftest()
    print("=== J. 代码指纹判据（合成仓库）===")
    cfp_ok = code_fingerprint_selftest()
    all_ok = (rc == 0 and ok and scope_rc == 0 and gap_ok
              and runbind_ok and airgap_scope_ok and attdep_ok and reg_ok
              and temp_ok and cfp_ok)
    print("链路自测：%s" % ("PASS" if all_ok else "FAIL"))
    return 0 if all_ok else 1


def scope_selftest():
    """合成数据验证 claim_scope 的三值判定（不是评测结果）。"""
    tmpdir = os.path.join(WORKDIR, "_scope_selftest")
    os.makedirs(tmpdir, exist_ok=True)
    pool_p = os.path.join(tmpdir, "private_pool.json")
    audit_p = os.path.join(tmpdir, "private_audit.json")
    results = []

    def check(name, got, want):
        good = got == want
        results.append(good)
        print("  %s %-40s got=%-30s want=%s" %
              ("PASS" if good else "FAIL", name, got, want))

    # 1. 真实干净池（160 题全公开）→ 只能作工程回归读数
    check("公开池 → engineering_regression_only",
          claim_scope_for_pool()["claim_scope"], "engineering_regression_only")
    check("干净池题面自曝答案题被重算出（门禁空洞绿）",
          claim_scope_for_pool()["statement_tainted_count"] > 0, True)
    # 1b. v2 交付件必须存在且干净（缺件即红，fail-closed）
    if not (os.path.isfile(POOL_V2) and os.path.isfile(PRIOR_AUDIT_V2)):
        print("  FAIL v2 池/题源证据缺失（fail-closed）")
        results.append(False)
    else:
        s2 = claim_scope_for_pool(POOL_V2, PRIOR_AUDIT_V2)
        check("v2 池自曝题=0", s2["statement_tainted_count"], 0)
        check("v2 仍为工程回归读数", s2["claim_scope"], "engineering_regression_only")
        check("v2 题源证据一致", s2["audit_evidence_consistent"], True)
    # 2. 绑定指纹不一致 → fail-closed
    check("结果绑定池指纹不一致 → unverified",
          claim_scope_for_pool(bound_pool_sha="0" * 64)["claim_scope"], "unverified")

    private = {"benchmark": "synthetic", "problems": {
        "q1": {"id": "q1", "name": "q1", "pool": "mine",
               "description": "一道本地生成的数学题",
               "source": "private self-authored", "created_at": "2026-10-01"},
        "q2": {"id": "q2", "name": "q2", "pool": "mine",
               "description": "另一道本地生成的数学题",
               "source": "private self-authored", "created_at": "2026-10-02"},
    }}
    with open(pool_p, "w", encoding="utf-8") as f:
        json.dump(private, f, ensure_ascii=False)
    with open(audit_p, "w", encoding="utf-8") as f:
        json.dump(audit_pool_prior.audit(pool_p), f, ensure_ascii=False)
    # 3. §17：题面自证全私有 + 证据一致，但无外部锚点 ⇒ 不给能力率
    s3 = claim_scope_for_pool(pool_p, audit_p)
    check("仅题面自证全私有 → engineering_regression_only",
          s3["claim_scope"], "engineering_regression_only")
    check("无锚点时 private_proof_anchored=False",
          s3["private_proof_anchored"], False)
    # 3c. registry 路径必须是可覆盖的显式参数：扩池后若沿用默认注册表，
    #     R0 的 pool_sha256 会对不上。覆盖后"没有可用锚点"必须降级，
    #     而不是悄悄沿用上一个池的 anchored=True（换池洗白的另一条路径）。
    miss_reg = os.path.join(tmpdir, "registry_missing.json")
    s3c = claim_scope_for_pool(pool_p, audit_p, registry_path=miss_reg)
    check("registry 路径可覆盖（作用域如实记录）",
          s3c["private_proof_registry_path"],
          os.path.relpath(miss_reg, ROOT).replace("\\", "/"))
    check("覆盖到缺失注册表 ⇒ anchored=False",
          s3c["private_proof_anchored"], False)
    # 3b. 证明 capability_rate_candidate 不是不可达红灯：注入一份合规锚点结论。
    #     仅本自测局部打桩；生产调用路径没有任何注入参数。
    from unittest import mock
    with mock.patch.object(audit_private_proof, "assess",
                            return_value={"anchored": True, "anchored_count": 2,
                                         "reasons": [], "total": 2}):
        s3b = claim_scope_for_pool(pool_p, audit_p)
    check("外部锚点成立 → capability_rate_candidate（分支可达）",
          s3b["claim_scope"], "capability_rate_candidate")
    # 3c. 真实公开池同样不得被算成已锚定
    check("真实公开池无外部锚点",
          claim_scope_for_pool()["private_proof_anchored"], False)
    # 4. 证据漂移 → unverified
    drifted = audit_pool_prior.audit(pool_p)
    drifted["counts"]["private_proven"] = 0
    with open(audit_p, "w", encoding="utf-8") as f:
        json.dump(drifted, f, ensure_ascii=False)
    check("审计证据漂移 → unverified",
          claim_scope_for_pool(pool_p, audit_p)["claim_scope"], "unverified")
    # 5. 证据缺失 → unverified
    os.remove(audit_p)
    check("审计证据缺失 → unverified",
          claim_scope_for_pool(pool_p, audit_p)["claim_scope"], "unverified")

    os.remove(pool_p)
    try:
        os.rmdir(tmpdir)
    except OSError:
        pass
    print("  作用域自测 %d/%d" % (sum(results), len(results)))
    return 0 if all(results) else 1


def main():
    ap = argparse.ArgumentParser(description="合规能力评测入口（前置守卫+自动证据+判分）")
    ap.add_argument("--mode", choices=("pure_llm", "agentic"), default="pure_llm",
                    help="评测路径：pure_llm=无工具出口(默认)，agentic=有解题子进程需 seccomp/IP 直连证明")
    ap.add_argument("--preflight", action="store_true", help="只验前置并写 evidence.auto.json")
    ap.add_argument("--adjudicate", metavar="RESULT_JSON", help="用已有跑批结果判分")
    ap.add_argument("--run", action="store_true", help="前置通过后执行 -- 之后的跑批命令")
    ap.add_argument("--result", help="跑批输出路径（--run 时用于判分）")
    ap.add_argument("--airgap-proof", help="IP 直连探测结果 json")
    ap.add_argument("--legacy-evidence", help="历史批次自带证据（归因旧结果时用，不冒充新评测）")
    ap.add_argument("--pool", default=POOL,
                    help="本批次题池（默认 v1；v1 含 6 道自曝题，前置守卫会拒绝新跑批）")
    ap.add_argument("--manifest", default=MANIFEST, help="题池指纹 manifest")
    ap.add_argument("--prior-audit", default=PRIOR_AUDIT,
                    help="题源先验审计证据（换池必须同步换，否则 claim_scope=unverified）")
    ap.add_argument("--registry", default=PRIVATE_PROOF_REGISTRY,
                    help=("私有性外部锚点注册表（默认 v1；扩池后必须指向与 --pool 同源的"
                          "注册表，否则 R0 的 pool_sha256 对不上 ⇒ anchored=False）"))
    ap.add_argument("--out", default=os.path.join(WORKDIR, "verdict.auto.json"))
    ap.add_argument("--selftest", action="store_true",
                    help="链路自测：判据变异验证 + 合成合规批次的正向结论（不是评测结果）")
    ap.add_argument("--annotate", metavar="VERDICT_JSON",
                    help="给已有 verdict 追加题源先验作用域（只加字段，不重判、不改原有字段）")
    ap.add_argument("--gap-result", metavar="RESULT_JSON",
                    help="--annotate 时连同判分假阴性片段一起追加（从该跑批结果重算）")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="-- 之后的跑批命令")
    args = ap.parse_args()

    if args.selftest:
        return pipeline_selftest()

    if args.annotate:
        if not os.path.isfile(args.annotate):
            print("verdict 不存在: %s" % args.annotate, file=sys.stderr)
            return 2
        with open(args.annotate, encoding="utf-8") as f:
            v = json.load(f)
        mutable = ("claim_scope", "scoring_variant_gap")
        before = {k: x for k, x in v.items() if k not in mutable}
        ev = v.get("evidence")
        bound = ev.get("result_pool_sha256") if isinstance(ev, dict) else None
        scope = claim_scope_for_pool(pool_path=args.pool, audit_path=args.prior_audit,
                                    bound_pool_sha=bound,
                                    registry_path=args.registry)
        v["claim_scope"] = scope
        if args.gap_result:
            v["scoring_variant_gap"] = scoring_gap_fragment(args.gap_result)
        after = {k: x for k, x in v.items() if k not in mutable}
        if before != after:
            print("拒绝写回：原有判分字段被改动", file=sys.stderr)
            return 2
        with open(args.annotate, "w", encoding="utf-8") as f:
            json.dump(v, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print("已追加结论作用域（原有判分字段逐键比对未变）：%s" %
              os.path.relpath(args.annotate, ROOT))
        print("  claim_scope=%s  private_proven=%s/%s  reason=%s" %
              (scope["claim_scope"], scope["private_proven"], scope["total"],
               scope["reason"]))
        if "scoring_variant_gap" in v:
            print("  判分不去壳假阴性=%s 题" %
                  v["scoring_variant_gap"].get("false_negative_count"))
        return 0

    ok, checks, ev = preflight(args)
    print("=== 前置守卫 ===")
    for c in checks:
        tag = ("N/A " if c.get("na") else
               "WARN" if c.get("warn") and not c["ok"] else
               "OK " if c["ok"] else "FAIL")
        print("  %s %-38s %s" % (tag, c["item"], c["note"]))
    os.makedirs(WORKDIR, exist_ok=True)
    with open(EVIDENCE_PATH, "w", encoding="utf-8") as f:
        json.dump(ev, f, ensure_ascii=False, indent=2)
    print("自动证据：%s" % os.path.relpath(EVIDENCE_PATH, ROOT))

    if args.preflight:
        if not ok:
            print("前置未通过 → 拒绝跑批（fail-closed）。缺项必须先补齐，不放行任何能力率。")
            return 2
        print("前置通过。可以执行 --run 或 --adjudicate。")
        return 0

    def report(v):
        print("=== 判分仲裁 ===")
        print("有效开跑 %d / 原始命中 %d / LLM_SOLVED %d / CLEAN_FAIL %d / NOT_ATTRIBUTABLE %d"
              % (v["effective_runs"], v["raw_solved_hits"], v["verdicts"]["LLM_SOLVED"],
                 v["verdicts"]["CLEAN_FAIL"], v["verdicts"]["NOT_ATTRIBUTABLE"]))
        try:
            out_disp = os.path.relpath(args.out, ROOT)
        except ValueError:  # Windows 跨盘绝对路径（如 C:\tmp 与 E:\repo）
            out_disp = args.out
        print("可引用=%s 链路读数=%s 逐题明细=%s"
              % (v["claimable"], v["capability_rate"], out_disp))
        scope = v.get("claim_scope") or {}
        kind = scope.get("claim_scope", "unverified")
        print("结论作用域=%s 私有题=%s/%s 审计证据一致=%s"
              % (kind, scope.get("private_proven"), scope.get("total"),
                 scope.get("audit_evidence_consistent")))
        if kind != "capability_rate_candidate":
            print("[!] 本批次数值仅为工程回归读数，不得对外称为能力率；原因：%s"
                  % scope.get("reason", "作用域未验证"))
        if scope.get("statement_tainted_count"):
            print("[!] 分母含 %d 道题面自曝答案题（明文门禁空洞绿），题号见 verdict.claim_scope.statement_tainted_ids"
                  % scope["statement_tainted_count"])
        for lim in scope.get("pool_known_limitations", []):
            print("[!] 池已知限制：%s" % lim)
        if not scope.get("private_proof_anchored"):
            print("[!] 私有性无外部锚点（%s）⇒ 题面自证全私有也不得称能力率"
                  % scope.get("private_proof_reason", "未验证"))
        gap = v.get("scoring_variant_gap") or {}
        n_gap = gap.get("false_negative_count")
        if n_gap:
            print("[!] 判分不去壳假阴性 %d 题（模型答对却判不中）；题号见 verdict.scoring_variant_gap"
                  % n_gap)
        elif n_gap is None:
            print("[!] 判分假阴性审计失败/缺失：本批次读数不得视为无偏差")
        dep = v.get("attachment_dependency") or {}
        n_dep = dep.get("attachment_dependent_count")
        if n_dep:
            print("[!] 结构不可解 %d/%s 题（题面引用外部文件、本路径未提供附件）⇒ "
                  "0 命中不等于模型不会；题号见 verdict.attachment_dependency"
                  % (n_dep, dep.get("batch_size")))
        elif n_dep is None:
            print("[!] 结构可解性审计失败/缺失：本批次读数不得视为模型能力结论")
        return 0 if v["claimable"] else 1

    # 历史批次归因：不受前置失败阻挡 —— 判据的价值正是把不合格批次判成不可归因。
    # 用自动证据（含 preflight_passed=false）或该批次自带的 legacy 证据，绝不冒充新评测。
    if args.adjudicate and not args.run:
        ev_use = ev
        if args.legacy_evidence:
            ev_use = json.load(open(args.legacy_evidence, encoding="utf-8"))
            ev_use["_mode"] = "legacy_attribution"
        else:
            ev_use["_mode"] = "auto_evidence(preflight_passed=%s)" % ok
        return report(adjudicate(args.adjudicate, ev_use, args.out, args.mode,
                                 auto_prove=not args.legacy_evidence,
                                 pool=args.pool, prior_audit=args.prior_audit,
                                 registry=args.registry))

    if not ok:
        print("前置未通过 → 拒绝跑批（fail-closed）。缺项必须先补齐，不放行任何能力率。")
        return 2
    if args.run:
        cmd = [x for x in args.command if x != "--"]
        if not cmd:
            print("--run 需要 -- 之后的命令", file=sys.stderr)
            return 2
        # 注意：下面这个键只证明「命令参数里的 --benchmark 池」，
        # **不证明结果文件内容**。第十一个偏差实测：命令 rc=0 却不写结果、
        # 或 rc=7 失败，旧实现都照样拿旧结果判分并让该指纹自证成立。
        # 真正的绑定在跑批后由 verify_run_result() 做结果级校验。
        bench = None
        for i, x in enumerate(cmd):
            if x == "--benchmark" and i + 1 < len(cmd):
                bench = cmd[i + 1]
                break
        bp = bench and (bench if os.path.isabs(bench) else os.path.join(ROOT, bench))
        ev["result_pool_sha256"] = _sha256(bp) if bp and os.path.isfile(bp) else None
        print("命令参数题池：%s sha=%s（仅参数，非结果级证明）"
              % (bench, str(ev["result_pool_sha256"])[:16]))
        # 路径规范化：跑批子进程 cwd=ROOT，主进程 cwd 未必是 ROOT；
        # 相对路径在两侧会指向不同文件 ⇒ 判分读不到本次结果。
        result_path = args.result
        if result_path and not os.path.isabs(result_path):
            result_path = os.path.join(ROOT, result_path)
        before = snapshot_result(result_path)
        started_ns = time.time_ns()
        print("执行跑批：%s" % " ".join(cmd))
        rc = subprocess.call(cmd, cwd=ROOT)
        print("跑批 rc=%d" % rc)
        if not args.result:
            return rc
        ok_run, why = verify_run_result(result_path, before, args.pool, rc, started_ns)
        if not ok_run:
            print("[FAIL] 拒绝判分：本次跑批结果不成立（fail-closed）", file=sys.stderr)
            for reason in why:
                print("  - %s" % reason, file=sys.stderr)
            print("  旧实现会把命令参数指纹当成结果池绑定，读旧结果继续判分。",
                  file=sys.stderr)
            return 2
        ev["result_file_sha256"] = _sha256(result_path)
        ev["result_written_by_this_run"] = True
        ev["result_ids_in_pool_proven"] = True
        print("结果级绑定：OK（本次写入 sha=%s，题 id 全在本批次池内）"
              % ev["result_file_sha256"][:16])
        return report(adjudicate(result_path, ev, args.out, args.mode, cmd,
                                  pool=args.pool, prior_audit=args.prior_audit,
                                  registry=args.registry))
    return 0


if __name__ == "__main__":
    sys.exit(main())
