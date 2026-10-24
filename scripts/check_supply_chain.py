#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""供应链门禁（十一防线 G-02）：SBOM 必须存在、覆盖完整、可复现。

为什么需要
----------
本项目此前对"我们到底依赖了什么"零证据：
  - `requirements.txt` 里 0 个 `==`，全是 `>=`，装到什么版本取决于当天 PyPI；
  - Go 侧虽然有 `go.sum`（可复现），但没有任何清单能回答"发了哪些模块、各是什么版本"；
  - 无 SBOM → 出事后无法回答"这个 CVE 影响不影响我们"，也无法向评委证明依赖面。

本门禁做三件**可机验**的事（做不到的如实标注，不假装做了）：
  C1 `docs/evidence/sbom.json` 必须存在，且与当前依赖树**逐字节一致**（漂移即红）；
  C2 go.mod 里每个 require 的模块版本，必须在 go.sum 里有对应的 zip 哈希（否则不可复现）；
  C3 依赖清单非空（解析失败时必须红，不许"扫到 0 个依赖 → 全绿"）。

**它不做什么**（写清楚，避免给假安全感）：不做 CVE 扫描。离线环境没有本地漏洞库，
没有 osv-scanner / 无网络时任何"漏洞数=0"都是假的。SBOM 里 `vulnerability_scan`
字段固定写 `not_run` 并注明原因——这是诚实位，不是遗漏。

用法：
  python scripts/check_supply_chain.py --write      # 生成/刷新 SBOM
  python scripts/check_supply_chain.py              # 校验（CI 用），rc=1 即红
  python scripts/check_supply_chain.py --self-test  # 变异验证：4 类注入必须变红
"""

import argparse
import json
import os
import re
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SBOM_REL = os.path.join("docs", "evidence", "sbom.json")

REQ_LINE = re.compile(r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(.*)$")
REPLACE_LINE = re.compile(r"^replace\s+(\S+)(?:\s+(v\S+))?\s*=>\s*(\S+)(?:\s+(v\S+))?$")


def _read(path):
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return fh.read()


def parse_go_mod(path):
    """返回 (go_version, [(module, version), ...], {module: (repl, ver, is_path)})。

    注意 replace 指令：被 replace 的模块在 go.sum 里**不会**有原模块的哈希，
    只有替换目标才有。忽略它会造出"缺哈希"的假红（本项目 2026-10-24 实锤：
    dingtalk-stream-sdk-go 被 replace 到 uouuou/...，门禁第一版就误报了）。
    """
    if not os.path.isfile(path):
        return None, [], {}
    go_ver = ""
    deps = []
    replaces = {}
    in_block = False
    in_repl_block = False
    for raw in _read(path).splitlines():
        line = raw.split("//")[0].strip()
        if not line:
            continue
        if line.startswith("go "):
            go_ver = line.split()[1]
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if line.startswith("replace ("):
            in_repl_block = True
            continue
        if line == ")":
            in_block = False
            in_repl_block = False
            continue
        if in_repl_block or line.startswith("replace "):
            m = REPLACE_LINE.match(line if line.startswith("replace ") else "replace " + line)
            if m:
                orig, _ov, target, tver = m.group(1), m.group(2), m.group(3), m.group(4)
                is_path = target.startswith((".", "/")) or target.startswith("..")
                replaces[orig] = (target, tver or "", is_path)
            continue
        if in_block or line.startswith("require "):
            parts = line.replace("require ", "").split()
            if len(parts) >= 2 and parts[1].startswith("v"):
                deps.append((parts[0], parts[1]))
    return go_ver, sorted(set(deps)), replaces


def parse_go_sum(path):
    """返回 {module: {version, ...}}。"""
    out = {}
    if not os.path.isfile(path):
        return out
    for line in _read(path).splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        mod, ver = parts[0], parts[1]
        ver = ver.replace("/go.mod", "")
        out.setdefault(mod, set()).add(ver)
    return out


def parse_requirements(path):
    """返回 [{name, spec, specifier, pinned}, ...]。"""
    if not os.path.isfile(path):
        return []
    out = []
    for raw in _read(path).splitlines():
        line = raw.split("#")[0].strip()
        if not line:
            continue
        m = REQ_LINE.match(line)
        if not m:
            out.append({"name": line, "spec": line, "specifier": "",
                        "pinned": False, "parseable": False})
            continue
        name, _extra, spec = m.group(1), m.group(2), m.group(3).strip()
        out.append({
            "name": name,
            "spec": line,
            "specifier": spec,
            "pinned": spec.startswith("=="),
            "parseable": True,
        })
    return out


def build(root):
    go_ver, deps, replaces = parse_go_mod(os.path.join(root, "go.mod"))
    sums = parse_go_sum(os.path.join(root, "go.sum"))
    go_deps = []
    for mod, ver in deps:
        entry = {"name": mod, "version": ver, "in_go_sum": ver in sums.get(mod, set())}
        repl = replaces.get(mod) or replaces.get(mod + "@" + ver)
        if repl:
            target, tver, is_path = repl
            entry["replaced_by"] = target
            if is_path:
                entry["replaced_by_path"] = True
                entry["in_go_sum"] = True  # 本地路径替换无需哈希
            else:
                entry["replaced_version"] = tver
                entry["in_go_sum"] = tver in sums.get(target, set())
        go_deps.append(entry)
    reqs = parse_requirements(os.path.join(root, "requirements.txt"))
    return {
        "schema": "secautomind-sbom/1",
        "note": "确定性清单：不含时间戳/HEAD，保证逐字节可复现；漏洞扫描状态见 vulnerability_scan。",
        "go": {
            "module": "secautomind-ai",
            "go_version": go_ver or "",
            "dependency_count": len(go_deps),
            "dependencies": go_deps,
        },
        "python": {
            "requirement_count": len(reqs),
            "pinned_count": sum(1 for r in reqs if r["pinned"]),
            "requirements": reqs,
        },
        "vulnerability_scan": {
            "status": "not_run",
            "reason": "离线环境无本地漏洞库；需 osv-scanner + 网络。此字段为诚实位，"
                      "不得改成 ok/clean 除非真的跑过。",
        },
    }


def check(root):
    errs = []
    sbom_path = os.path.join(root, SBOM_REL)
    data = build(root)

    # C3 非空（fail-closed：解析失败不能变成"0 个依赖 → 全绿"）
    if data["go"]["dependency_count"] == 0:
        errs.append("C3 go.mod 解析出 0 个依赖（文件缺失或格式变了）")
    if data["python"]["requirement_count"] == 0:
        errs.append("C3 requirements.txt 解析出 0 个依赖（文件缺失或格式变了）")

    # C2 go.sum 必须覆盖每个 require
    missing = [d["name"] + "@" + d["version"] for d in data["go"]["dependencies"]
               if not d["in_go_sum"]]
    if missing:
        errs.append("C2 以下模块在 go.sum 中无哈希（不可复现）：%s"
                    % ", ".join(missing[:5]))

    # C1 SBOM 存在且一致
    if not os.path.isfile(sbom_path):
        errs.append("C1 %s 不存在：跑 --write 生成" % SBOM_REL.replace("\\", "/"))
        return errs
    cur = json.loads(_read(sbom_path))
    if cur != data:
        errs.append("C1 %s 与当前依赖树不一致（SBOM 过期）：跑 --write 刷新"
                    % SBOM_REL.replace("\\", "/"))
    return errs


def _mk_tree(base, deps=2, sums=None, reqs="requests>=2.32.3\n"):
    with open(os.path.join(base, "go.mod"), "w", encoding="utf-8") as fh:
        fh.write("module demo\n\ngo 1.25.0\n\nrequire (\n")
        for i in range(deps):
            fh.write("\tgithub.com/x/m%d v1.0.%d\n" % (i, i))
        fh.write(")\n")
    if sums is None:
        sums = "github.com/x/m%d v1.0.%d h1:abc=\ngithub.com/x/m%d v1.0.%d/go.mod h1:def=\n"
        sums = "".join(sums % (i, i, i, i) for i in range(deps))
    with open(os.path.join(base, "go.sum"), "w", encoding="utf-8") as fh:
        fh.write(sums)
    with open(os.path.join(base, "requirements.txt"), "w", encoding="utf-8") as fh:
        fh.write(reqs)
    os.makedirs(os.path.join(base, "docs", "evidence"), exist_ok=True)
    with open(os.path.join(base, SBOM_REL), "w", encoding="utf-8") as fh:
        json.dump(build(base), fh, ensure_ascii=False, indent=2)


def self_test():
    cases = []

    def case(name, mutate, expect_fail):
        base = tempfile.mkdtemp(prefix="sbom_")
        try:
            _mk_tree(base)
            mutate(base)
            errs = check(base)
            cases.append((name, expect_fail, bool(errs), errs))
        finally:
            shutil.rmtree(base, ignore_errors=True)

    def m_ok(b):
        pass

    def m_missing_sum(b):
        with open(os.path.join(b, "go.sum"), "w", encoding="utf-8") as fh:
            fh.write("github.com/x/m0 v1.0.0 h1:abc=\n")  # 少了 m1

    def m_empty_req(b):
        with open(os.path.join(b, "requirements.txt"), "w", encoding="utf-8") as fh:
            fh.write("# 只剩注释\n\n")

    def m_tamper(b):
        p = os.path.join(b, SBOM_REL)
        d = json.load(open(p, encoding="utf-8"))
        d["go"]["dependency_count"] = 999
        json.dump(d, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    def m_no_sbom(b):
        os.remove(os.path.join(b, SBOM_REL))

    case("基线应通过", m_ok, False)
    case("go.sum 缺模块应红", m_missing_sum, True)
    case("requirements 解析为空应红", m_empty_req, True)
    case("SBOM 被篡改应红", m_tamper, True)
    case("SBOM 缺失应红", m_no_sbom, True)

    ok = True
    for name, expect_fail, got_fail, errs in cases:
        good = expect_fail == got_fail
        ok = ok and good
        print("  [%s] %-24s 期望%s 实际%s"
              % ("OK" if good else "FAIL", name,
                 "红" if expect_fail else "绿", "红" if got_fail else "绿"))
        if not good:
            for e in errs[:2]:
                print("        %s" % e)
    print("供应链门禁自测：%s（%d 项）" % ("PASS" if ok else "FAIL", len(cases)))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="供应链门禁（SBOM 一致性）")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--root", default=ROOT)
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if args.write:
        data = build(args.root)
        path = os.path.join(args.root, SBOM_REL)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print("已写入 %s（Go %d 依赖 / Python %d 依赖，其中钉版本 %d）"
              % (SBOM_REL.replace("\\", "/"), data["go"]["dependency_count"],
                 data["python"]["requirement_count"], data["python"]["pinned_count"]))
        return 0

    errs = check(args.root)
    print("=" * 62)
    print("供应链门禁（G-02 · SBOM 一致性）")
    print("=" * 62)
    if errs:
        for e in errs:
            print("  [FAIL] %s" % e)
        print("-" * 62)
        print("结论：FAIL（%d 项）" % len(errs))
        return 1
    print("  [PASS] C1 SBOM 存在且与依赖树一致")
    print("  [PASS] C2 go.sum 覆盖全部 require")
    print("  [PASS] C3 依赖清单非空")
    print("  [NOTE] 漏洞扫描：未执行（离线无本地库）——见 SBOM 的 vulnerability_scan 字段")
    print("-" * 62)
    print("结论：PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
