#!/usr/bin/env python3
"""真实赛题池的准入审计：污染 / 结构可解性 / 分母资格（只读，不改池）。

## 为什么要这个脚本

2026-11-07 决定把外部赛题池（Google CTF 2021-2025，40 题）拿来当「真刀」跑批时，
发现三类题会让读数变味，而它们在跑之前完全看不出来：

  ① 污染：附件里就带着答案（`flag` / `flag.txt` 这类文件名在池里真实存在）
     ⇒ 模型「读文件」而不是「解题」，命中率高但意义为零。
  ② 硬不可用：题目必须**执行**沙箱给不了的运行时（.rom 要模拟器、原生二进制要跑）
     ⇒ 失败是环境不行，不是能力不行；计入分母就是把工程缺陷算成能力缺陷。
  ③ 软受限：需要 sage / go / dart / 反编译，但可以用标准库或纯 Python 绕过
     ⇒ 仍算能力边界，只在证据里标注，不剔分母。

关键教训（F-13）：**不能因为「看起来难」就把题剔出分母**，也不能反过来
因为「有附件」就假定可解。判据必须是机算的、可复现的。

## 口径

- 污染判定：附件任意文件的整字节 / 内嵌 token / 任意一行裸内容，
  其 sha256 等于本题 `flag_sha256` ⇒ 判污染。
- 硬不可用：`.rom` / `.so` / 非 .so 的原生可执行（ELF/MZ magic）。
- 软受限：`.sage` / `.go` / `.dart` / `.pyc` / `.zip`。
- `admissible_denominator` = 总题数 - 污染 - 硬不可用。

用法：
  python scripts/audit_external_pool_readiness.py --check              # RC=1 表示有题不合格
  python scripts/audit_external_pool_readiness.py --json               # 机器可读
  python scripts/audit_external_pool_readiness.py --selftest           # 证明分级能变红
"""
import argparse
import hashlib
import json
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_POOL = os.path.join(ROOT, "data", "questions_external_bench", "external_bench.json")
DEFAULT_ATT = os.path.join(ROOT, "data", "questions_external_bench", "_attachments")

HARD_UNAVAILABLE = {
    ".rom": "需模拟器执行（禁 subprocess）",
    ".so": "需原生动态加载",
}
SOFT_CONSTRAINED = {
    ".sage": "sagemath 缺失，数学可纯 Python 复现",
    ".go": "golang 缺失，可读源码分析协议",
    ".dart": "dart 缺失，可读源码分析协议",
    ".pyc": "需 marshal/dis 反编译（标准库可做）",
    ".zip": "需 zipfile 解压（标准库可做）",
}
BIN_MAGIC = (b"\x7fELF", b"MZ")
DATA_PREFIX = ("output", "out.txt", "cipher", "dump", "ct", "enc", "data",
               "public", "pub", "params", "flag_enc", "json", "pem")


def _sha(b):
    if isinstance(b, bytes):
        return hashlib.sha256(b).hexdigest()
    return hashlib.sha256(str(b).encode("utf-8")).hexdigest()


def scan_attachment_for_answer(att_dir, want_sha, max_bytes=4 * 1024 * 1024):
    """在题目附件目录里找是否有东西能直接得出真值。返回命中列表或 None。"""
    if not os.path.isdir(att_dir):
        return None
    hits = []
    for root, _dirs, names in os.walk(att_dir):
        for n in sorted(names):
            fp = os.path.join(root, n)
            rel = os.path.relpath(fp, att_dir)
            try:
                raw = open(fp, "rb").read(max_bytes)
            except OSError:
                continue
            if _sha(raw) == want_sha:
                hits.append({"file": rel, "how": "whole-file-bytes"})
                continue
            text = raw.decode("utf-8", "replace")
            embedded = False
            for tok in re.findall(r"[A-Za-z0-9_]{2,20}\{[^{}\n]{1,120}\}", text):
                # 真值可能登记为裸内容而附件里是带壳形态（反过来也有），必须双向归一。
                # 只比原串会漏掉「附件写着 flag{X}、真值是 sha256(X)」这一整类（自测实测漏）。
                inner = tok[tok.index("{") + 1:-1]
                cands = {tok, inner, "flag{" + inner + "}"}
                if any(_sha(c) == want_sha for c in cands):
                    hits.append({"file": rel, "how": "embedded-token",
                                 "form": "wrapped", "len": len(tok)})
                    embedded = True
                    break
            if embedded:
                continue
            for line in text.splitlines():
                s = line.strip()
                if 4 <= len(s) <= 120 and _sha(s) == want_sha:
                    hits.append({"file": rel, "how": "bare-line", "len": len(s)})
                    break
    return hits or None


def classify_runtime(att_dir, files):
    """返回 (hard, soft) 两个列表。"""
    hard, soft = [], []
    for f in files:
        ext = os.path.splitext(f)[1].lower()
        if ext in HARD_UNAVAILABLE:
            hard.append("%s(%s)" % (ext, HARD_UNAVAILABLE[ext]))
        elif ext in SOFT_CONSTRAINED:
            soft.append("%s(%s)" % (ext, SOFT_CONSTRAINED[ext]))
        fp = os.path.join(att_dir, f)
        try:
            head = open(fp, "rb").read(4)
        except OSError:
            continue
        if head.startswith(BIN_MAGIC) and ext != ".so":
            hard.append("%s(原生二进制，需执行才能观察行为)" % f)
    return sorted(set(hard)), sorted(set(soft))


def has_data_file(files):
    return any(any(f.lower().startswith(k) for k in DATA_PREFIX) for f in files)


def _rel(p):
    """相对仓库根的路径；跨盘符（Windows 临时目录在 C:）时回退为绝对路径。"""
    try:
        return os.path.relpath(p, ROOT).replace("\\", "/")
    except ValueError:
        return p.replace("\\", "/")


def audit(pool_path, att_root):
    d = json.load(open(pool_path, encoding="utf-8"))
    probs = d.get("problems", d)
    vals = list(probs.values()) if isinstance(probs, dict) else probs

    rows = []
    for v in vals:
        pid = v["id"]
        adir = os.path.join(att_root, pid)
        files = sorted(os.listdir(adir)) if os.path.isdir(adir) else []
        want = str(v.get("flag_sha256") or "").lower()
        contam = scan_attachment_for_answer(adir, want) if re.fullmatch(r"[0-9a-f]{64}", want) else None
        hard, soft = classify_runtime(adir, files)
        rows.append({
            "id": pid, "category": v.get("category"), "files": files,
            "contaminated": contam, "hard_unavailable": hard, "soft_constrained": soft,
            "has_data_file": has_data_file(files), "flag_sha256_12": want[:12],
        })

    contam = [r for r in rows if r["contaminated"]]
    hard = [r for r in rows if r["hard_unavailable"]]
    soft = [r for r in rows if r["soft_constrained"] and not r["hard_unavailable"]]
    clean = [r for r in rows if not r["contaminated"] and not r["hard_unavailable"]]
    return {
        "pool": _rel(pool_path),
        "attachments": _rel(att_root),
        "total": len(rows),
        "counts": {"contaminated": len(contam), "hard_unavailable": len(hard),
                   "soft_constrained": len(soft), "admissible": len(clean)},
        "admissible_denominator": len(clean),
        "tiers": {
            "A_static_complete": [r["id"] for r in clean if r["has_data_file"]],
            "B_needs_oracle": [r["id"] for r in clean if not r["has_data_file"]],
            "C_contaminated": [r["id"] for r in contam],
            "D_hard_unavailable": [r["id"] for r in hard],
            "E_soft_constrained": [r["id"] for r in soft],
        },
        "details": rows,
    }


def render(ev):
    c = ev["counts"]
    print("=" * 78)
    print("池: %s   题数: %d" % (ev["pool"], ev["total"]))
    print("=" * 78)
    if c["contaminated"]:
        print("\n🔴 [1] 附件污染（读文件即得答案）: %d 题" % c["contaminated"])
        for r in ev["details"]:
            if r["contaminated"]:
                print("    %-44s %s" % (r["id"], r["contaminated"]))
    else:
        print("\n✅ [1] 附件污染: 0 题")

    if c["hard_unavailable"]:
        print("\n🟠 [2] 硬不可用（必须执行拿不到的运行时）: %d 题" % c["hard_unavailable"])
        for r in ev["details"]:
            if r["hard_unavailable"]:
                print("    %-44s %s" % (r["id"], r["hard_unavailable"]))

    if c["soft_constrained"]:
        print("\n🟡 [3] 软受限（可绕过，仍计入能力）: %d 题" % c["soft_constrained"])

    t = ev["tiers"]
    print("\n[4] 分档")
    print("    A 静态数据完备        : %2d" % len(t["A_static_complete"]))
    print("    B 需自建 oracle       : %2d" % len(t["B_needs_oracle"]))
    print("    C 污染（剔分母）      : %2d" % len(t["C_contaminated"]))
    print("    D 硬不可用（剔分母）  : %2d" % len(t["D_hard_unavailable"]))
    print("\n可计分分母 = %d / %d" % (ev["admissible_denominator"], ev["total"]))


def selftest():
    """构造一个已知答案的合成池，验证三类判定都能变红、干净题不会误伤。"""
    ok = 0
    total = 0

    def ck(label, cond):
        nonlocal ok, total
        total += 1
        ok += int(bool(cond))
        print("%s %s" % ("PASS" if cond else "FAIL", label))

    with tempfile.TemporaryDirectory() as td:
        att = os.path.join(td, "att")
        os.makedirs(att)
        secret = "selftest_secret_value_42"
        bare_sha = _sha(secret)
        wrapped_sha = _sha("flag{%s}" % secret)

        def mk(pid, files):
            d = os.path.join(att, pid)
            os.makedirs(d, exist_ok=True)
            for name, content in files.items():
                p = os.path.join(d, name)
                os.makedirs(os.path.dirname(p), exist_ok=True) if os.path.dirname(p) else None
                mode = "wb" if isinstance(content, bytes) else "w"
                with open(p, mode) as f:
                    f.write(content)

        mk("p_clean", {"chall.py": "print(1)\n", "output.txt": "deadbeef\n"})
        mk("p_leak_whole", {"flag": "flag{%s}" % secret})
        mk("p_leak_plain", {"notes.txt": "the answer is flag{%s} ok\n" % secret})
        mk("p_rom", {"a.rom": b"\x00" * 64})
        mk("p_elf", {"chal": b"\x7fELF\x02\x01\x01" + b"\x00" * 32})
        mk("p_sage", {"c.sage": "R.<x>=ZZ[]\n", "output.txt": "1\n"})

        pool = {"problems": {
            "p_clean": {"id": "p_clean", "flag_sha256": _sha("flag{clean_answer}")},
            "p_leak_whole": {"id": "p_leak_whole", "flag_sha256": wrapped_sha},
            "p_leak_plain": {"id": "p_leak_plain", "flag_sha256": bare_sha},
            "p_rom": {"id": "p_rom", "flag_sha256": _sha("flag{rom}")},
            "p_elf": {"id": "p_elf", "flag_sha256": _sha("flag{elf}")},
            "p_sage": {"id": "p_sage", "flag_sha256": _sha("flag{sage}")},
        }}
        pp = os.path.join(td, "pool.json")
        json.dump(pool, open(pp, "w", encoding="utf-8"))

        ev = audit(pp, att)
        t = ev["tiers"]
        ck("整文件就是答案 → 判污染", "p_leak_whole" in t["C_contaminated"])
        ck("答案嵌在正文里 → 判污染", "p_leak_plain" in t["C_contaminated"])
        ck("干净题不得误判污染", "p_clean" not in t["C_contaminated"])
        ck(".rom → 硬不可用", "p_rom" in t["D_hard_unavailable"])
        ck("ELF magic → 硬不可用", "p_elf" in t["D_hard_unavailable"])
        ck(".sage → 软受限且不剔分母", "p_sage" in t["E_soft_constrained"]
           and "p_sage" not in t["D_hard_unavailable"])
        ck("分母 = 6 - 2 污染 - 2 硬不可用 = 2", ev["admissible_denominator"] == 2)
        ck("干净数据题进 A 档", "p_clean" in t["A_static_complete"])

        # 反向变异：把 sha 换成别的值，污染必须全部消失（证明判定真在比 sha，不是按文件名猜）
        pool2 = json.loads(json.dumps(pool))
        for v in pool2["problems"].values():
            v["flag_sha256"] = _sha("flag{unrelated}")
        pp2 = os.path.join(td, "pool2.json")
        json.dump(pool2, open(pp2, "w", encoding="utf-8"))
        ev2 = audit(pp2, att)
        ck("改真值后污染归零（判定真在比 sha256）",
           ev2["counts"]["contaminated"] == 0)

    print("\nselftest %d/%d" % (ok, total))
    return 0 if ok == total else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default=DEFAULT_POOL)
    ap.add_argument("--attachments", default=DEFAULT_ATT)
    ap.add_argument("--out", default=os.path.join(ROOT, ".workbuddy", "tmp",
                                                  "external_pool_readiness.json"))
    ap.add_argument("--json", action="store_true", help="只打 JSON")
    ap.add_argument("--check", action="store_true",
                    help="RC=1 表示存在污染或硬不可用题（分母被缩减）")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    ev = audit(args.pool, args.attachments)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(ev, f, ensure_ascii=False, indent=1)
    if args.json:
        print(json.dumps({k: ev[k] for k in ("pool", "total", "counts",
                                            "admissible_denominator", "tiers")},
                         ensure_ascii=False, indent=1))
    else:
        render(ev)
        print("\n写出 %s" % os.path.relpath(args.out, ROOT))
    if args.check and (ev["counts"]["contaminated"] or ev["counts"]["hard_unavailable"]):
        print("\n[BLOCK] 存在污染或硬不可用题：分母必须按 admissible_denominator 缩减",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
