#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""核对工作树里的 D 状态文件到底是「删除」还是「移动/整合」。

判定顺序（内容级，不看文件名猜）：
  1. MOVED   现存/未跟踪文件里存在 sha256 完全相同的副本
  2. MERGED  某个 _MERGED*.md 里出现了该文件正文的独特长行（>=2 行命中）
  3. HEADED  同目录下另有同名文件在 HEAD 且未删（= 重复对，另一份仍在）
  4. LOST    以上都不成立，内容只存在于 git 历史
"""
import hashlib
import os
import subprocess
import sys

ROOT = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True,
                      text=True, encoding="utf-8").stdout.strip()


def git(*args, **kw):
    return subprocess.run(["git", "-c", "core.quotePath=false"] + list(args),
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", cwd=ROOT, **kw).stdout


def head_bytes(path):
    r = subprocess.run(["git", "show", "HEAD:" + path], capture_output=True, cwd=ROOT)
    return r.stdout if r.returncode == 0 else b""


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    st = git("status", "--porcelain=v1")
    deleted = [l[3:].rstrip() for l in st.splitlines() if l[:2] in ("D ", " D")]

    # 现存文件（跟踪 + 未跟踪），用 git 列目录避免 Windows 设备节点
    live_paths = [p for p in git("ls-files").splitlines() if p]
    live_paths += [l[3:].rstrip() for l in st.splitlines() if l.startswith("??")]
    live = {}
    for p in live_paths:
        full = os.path.join(ROOT, p)
        if not os.path.isfile(full):
            continue
        try:
            if os.path.getsize(full) > 8 * 1024 * 1024:
                continue
            with open(full, "rb") as fh:
                live.setdefault(sha(fh.read()), []).append(p)
        except OSError:
            pass

    # 合并文档：行集合
    merged = {}
    for p in live_paths:
        if not (os.path.basename(p).startswith("_MERGED") and p.endswith(".md")):
            continue
        try:
            txt = open(os.path.join(ROOT, p), encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        merged[p] = {l.strip() for l in txt.splitlines() if len(l.strip()) >= 30}

    head_files = set(git("ls-tree", "-r", "HEAD", "--name-only").splitlines())

    rows = []
    for p in deleted:
        body = head_bytes(p)
        if not body:
            rows.append((p, "MISSING-IN-HEAD", ""))
            continue
        h = sha(body)
        # 1. 内容级移动
        if h in live:
            others = [x for x in live[h] if x != p]
            if others:
                rows.append((p, "MOVED", others[0]))
                continue
        # 2. 整合进 _MERGED
        try:
            text = body.decode("utf-8", "replace")
        except Exception:
            text = ""
        sig = [l.strip() for l in text.splitlines() if len(l.strip()) >= 40]
        sig = sig[:200]
        best, best_hit = "", 0
        for mp, mlines in merged.items():
            hit = sum(1 for l in sig if l in mlines)
            if hit > best_hit:
                best, best_hit = mp, hit
        if sig and best_hit >= 2 and best_hit >= len(sig) * 0.3:
            rows.append((p, "MERGED", "%s (%d/%d 行)" % (best, best_hit, len(sig))))
            continue
        # 3. 同目录同名副本仍在
        base = os.path.basename(p)
        twins = [f for f in head_files if os.path.basename(f) == base and f != p]
        twins = [f for f in twins if f not in deleted]
        if twins:
            rows.append((p, "HAS-TWIN", twins[0]))
            continue
        rows.append((p, "LOST", "sig=%d best=%d/%d" % (len(sig), best_hit, len(sig) or 1)))

    print("%-46s %-14s %s" % ("文件", "判定", "证据"))
    print("-" * 110)
    for p, verdict, ev in rows:
        print("%-46s %-14s %s" % (os.path.basename(p)[:44], verdict, ev))

    print()
    from collections import Counter
    c = Counter(v for _, v, _ in rows)
    for k, n in c.most_common():
        print("%-16s %d" % (k, n))

    lost = [r for r in rows if r[1] in ("LOST", "MISSING-IN-HEAD")]
    if lost:
        print("\n=== 需人工确认（无移动/整合痕迹）===")
        for p, v, ev in lost:
            print(" ", v, p, "|", ev)

    return 0


if __name__ == "__main__":
    sys.exit(main())
