#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把「已确认是答案的明文」换成人可读、机器不可抄的占位符。

为什么不直接删行：证据日志的价值在「这道题这一次解没解出、耗时多少」，
答案本身对证据没有任何价值。所以只换答案、保留行。

占位符形状 `<REDACTED:sha256=xxxxxxxx>`：**故意不带 `xxx{}` 花括号形态**，
这样连「像不像 flag」的启发式都不会命中，避免门禁自己给自己判红。

用法：
  python scripts/redact_answer_plaintext.py --dry-run            # 只看会改哪些文件
  python scripts/redact_answer_plaintext.py --apply              # 全仓应用
  python scripts/redact_answer_plaintext.py --apply --path docs/evidence --path 某文件
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_redaction_consistency as C  # noqa: E402


def _replacement(cand: str) -> str:
    h = C.hashlib.sha256(cand.encode("utf-8")).hexdigest()[:12]
    return "<REDACTED:sha256=%s>" % h


def redact_file(path: Path, known: dict, apply: bool) -> tuple[int, int]:
    """返回 (替换处数, 涉及字数)。只处理文本文件，二进制跳过。"""
    try:
        raw = path.read_bytes()
    except OSError:
        return 0, 0
    if b"\x00" in raw[:4096]:
        return 0, 0
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return 0, 0
    n = 0

    def _sub(m):
        nonlocal n
        cand = m.group(0)
        if "REDACTED" in cand:
            return cand
        h = C.hashlib.sha256(cand.encode("utf-8")).hexdigest()
        if h not in known:
            return cand
        n += 1
        return _replacement(cand)

    new = C.ANSWER_SHAPE.sub(_sub, text)
    if n and apply:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(new)
    return n, len(new)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="答案明文就地脱敏（保留行，只换答案）")
    ap.add_argument("--root", default=".")
    ap.add_argument("--path", action="append", default=[],
                    help="限定路径（相对 root，可多次）；缺省=全仓入仓文本文件")
    ap.add_argument("--apply", action="store_true", help="真正写盘（缺省只 dry-run）")
    args = ap.parse_args(argv)
    root = Path(args.root)
    known = C.collect_answer_hashes(root)

    targets: list[Path] = []
    if args.path:
        for rel in args.path:
            p = root / rel
            if p.is_dir():
                targets.extend(sorted(x for x in p.rglob("*") if x.is_file()))
            elif p.is_file():
                targets.append(p)
    else:
        for rel in C._scan_files(root):
            targets.append(root / rel)

    total = 0
    files = 0
    for p in targets:
        if p.suffix.lower() in C.ANSWER_SKIP_EXT:
            continue
        try:
            if p.stat().st_size > C.MAX_SCAN_BYTES:
                continue
        except OSError:
            continue
        n, _ = redact_file(p, known, args.apply)
        if n:
            files += 1
            total += n
            rel = p.relative_to(root).as_posix()
            print("%5d  %s%s" % (n, rel, "" if args.apply else "  (dry-run)"))
    print("%s：%d 处 ｜ %d 个文件" % ("已应用" if args.apply else "预演", total, files))
    if total and not args.apply:
        print("确认无误后加 --apply 落盘。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
