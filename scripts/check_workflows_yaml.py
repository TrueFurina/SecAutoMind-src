#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""workflow YAML 全文件强校验（2026-11-07 新增，G-01 同型缺口的补线）。

为什么存在：d90da85 在步骤名里写了未加引号的 `- name: ... (17 cases: ...)`，
块上下文纯标量不允许内嵌「: 」⇒ **整个 ci.yml 无效**。最讽刺的闭环是：
ci.yml 坏了时 CI 自己无法报错（workflow 加载失败 ≠ job 失败），于是那之后
加进 CI 的所有门禁在 GitHub 上一次都没跑过，而本机校验只看了 diff 没看全文件。

防线设计（两层，互为冗余）：
  1. pre-commit 本地拦截：本脚本挂在 scripts/git-hooks/pre-commit，
     yaml 解析失败 ⇒ 阻止提交（fail-closed）。
  2. ci_lint.yml 独立 workflow：即使 ci.yml 再坏，lint 自己仍能加载并报红。
     两个 workflow 文件互相盯不住对方？盯得住——lint 校验**所有** workflow
     文件，包括它自己；lint 自己坏了的话它加载时就报错。

降级语义：PyYAML 不可用时（部分本机环境），退化扫描已知失效类
（未加引号的 name/run/on 值内嵌「: 」）。这覆盖实测踩过的那类错误，
但不等于完整 YAML 校验——会如实打印 DEGRADED，不冒充强校验。

用法：
  python scripts/check_workflows_yaml.py            # 校验 .github/workflows/*.yml
  python scripts/check_workflows_yaml.py --selftest # 自测：喂一个坏样例必须报红
"""

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF_DIR = os.path.join(ROOT, ".github", "workflows")

# 已知失效类：块上下文的未加引号纯标量里出现「: 」（冒号+空格）。
# 实测（d90da85）：`- name: xxx (17 cases: ...)` 直接让整个文件解析失败。
# 只盯 `- name:`（实际咬人的那类）；裸 `- ` 会误伤合法的键值行，不作扫描。
_UNQUOTED_COLON = re.compile(r'^\s*- name: [^"\'].+: ')


def _parse(path):
    """返回 (ok, message)。优先 PyYAML 强校验；不可用则降级扫描。"""
    try:
        import yaml  # noqa: F401
        have_yaml = True
    except ImportError:
        have_yaml = False

    text = open(path, encoding="utf-8", errors="replace").read().replace("\r\n", "\n")
    if have_yaml:
        import yaml
        try:
            yaml.safe_load(text)
            return True, "PyYAML 解析通过"
        except yaml.YAMLError as exc:
            return False, "PyYAML 解析失败: %s" % str(exc).replace("\n", " ")[:160]
    # 降级：只扫已知失效类，如实标注不完整。
    hits = [i + 1 for i, l in enumerate(text.split("\n")) if _UNQUOTED_COLON.match(l)]
    if hits:
        return False, "降级扫描发现未加引号的内嵌冒号（行 %s）——本机无 PyYAML，未做完整校验" % hits
    return True, "DEGRADED：无 PyYAML，仅完成已知失效类扫描（未做完整解析）"


def check_all():
    files = sorted(glob.glob(os.path.join(WF_DIR, "*.yml")) + glob.glob(os.path.join(WF_DIR, "*.yaml")))
    if not files:
        print("check_workflows_yaml: 未找到任何 workflow 文件（异常，按失败处理）")
        return 1
    bad = 0
    degraded = False
    for f in files:
        ok, msg = _parse(f)
        rel = os.path.relpath(f, ROOT)
        print("%s %s  %s" % ("PASS" if ok else "FAIL", rel, msg))
        if not ok:
            bad += 1
        if "DEGRADED" in msg:
            degraded = True
    if degraded:
        print("\n[note] 本机无 PyYAML —— 本次仅降级扫描。完整校验由 ci_lint workflow（ubuntu, PyYAML 预装）兜底。")
    print("check_workflows_yaml: %d 文件, %d 失败" % (len(files), bad))
    return 1 if bad else 0


def _selftest():
    """喂已知坏样例必须报红；喂好样例必须通过。"""
    import tempfile
    bad = 'on: push\njobs:\n  a:\n    steps:\n      - name: x (17 cases: 坏样例)\n        run: echo hi\n'
    good = 'on: push\njobs:\n  a:\n    steps:\n      - name: "x (17 cases: 引号内安全)"\n        run: echo hi\n'
    d = tempfile.mkdtemp()
    p_bad = os.path.join(d, "wf_bad.yml")
    p_good = os.path.join(d, "wf_good.yml")
    open(p_bad, "w", encoding="utf-8", newline="\n").write(bad)
    open(p_good, "w", encoding="utf-8", newline="\n").write(good)
    ok = True
    r1 = _parse(p_bad)
    print("  %s 坏样例必须 FAIL（%s）" % ("PASS" if not r1[0] else "FAIL", r1[1][:70]))
    ok = ok and not r1[0]
    r2 = _parse(p_good)
    print("  %s 好样例必须 PASS（%s）" % ("PASS" if r2[0] else "FAIL", r2[1][:70]))
    ok = ok and r2[0]
    # 降级路径强制演练：屏蔽 yaml 模块再跑坏样例
    import builtins
    real_import = builtins.__import__

    def no_yaml(name, *a, **kw):
        if name == "yaml":
            raise ImportError("simulated")
        return real_import(name, *a, **kw)
    builtins.__import__ = no_yaml
    try:
        r3 = _parse(p_bad)
    finally:
        builtins.__import__ = real_import
    print("  %s 无 PyYAML 时坏样例仍须 FAIL（%s）" % ("PASS" if not r3[0] else "FAIL", r3[1][:70]))
    ok = ok and not r3[0]
    print("check_workflows_yaml selftest: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(_selftest() if "--selftest" in sys.argv else check_all())
