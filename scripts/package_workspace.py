#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SecAutoMind 工作区打包（P3：manifest + 人格文件 + agents/roles/skills）

把「协调主代理 + 专项子代理 + 角色 + 技能 + 人格」打成一个**可移植的工作区包**，
供导入另一个 SecAutoMind 实例，或作为统一的分发单元。

设计原则（为什么这样做）：
  - **加法式**：只读取 `agents/` `roles/` `skills/` 与 `workspace/`，不改动它们；
  - **单一真值源**：清单只声明 glob，实际文件由脚本发现并**校验**，避免清单与磁盘漂移；
  - **fail-closed**：任一资产格式不合法（agent 缺 id/name、role 缺 name、skill 的
    SKILL.md `name` 与目录名不一致）→ 拒绝出包（rc=1），绝不产出半成品；
  - **确定性**：归档内路径排序、mtime/uid/gid 归零，同一输入产出一致字节，便于哈希与复现。

用法：
    python scripts/package_workspace.py --check      # 只校验，不出包
    python scripts/package_workspace.py --list       # 列出将纳入的文件
    python scripts/package_workspace.py              # 产出 dist/secautomind-workspace-<ver>.tar.gz
    python scripts/package_workspace.py --out x.tar.gz

退出码：
    0 = 成功
    1 = 资产校验失败 / 人格文件缺失
    2 = 清单缺失或解析失败（环境/配置错误）
"""
import argparse
import json
import re
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT / "workspace"
MANIFEST = WS / "manifest.json"

_FM_RE = re.compile(r"^---\s*\n(.*?)\n---", re.S)
_NAME_RE = re.compile(r"^name:\s*(.+)$", re.M)
_ID_RE = re.compile(r"^id:\s*(.+)$", re.M)


def _front_matter(text: str) -> str:
    m = _FM_RE.match(text)
    return m.group(1) if m else ""


def _clean(v: str) -> str:
    return v.strip().strip('"').strip("'")


def validate_agent(p: Path) -> list:
    text = p.read_text(encoding="utf-8", errors="replace")
    fm = _front_matter(text)
    errs = []
    if not fm:
        errs.append("缺 YAML front matter")
    if not _ID_RE.search(fm):
        errs.append("front matter 缺 id")
    if not _NAME_RE.search(fm):
        errs.append("front matter 缺 name")
    return errs


def validate_role(p: Path) -> list:
    text = p.read_text(encoding="utf-8", errors="replace")
    return [] if _NAME_RE.search(text) else ["缺 name 字段"]


def validate_skill(skill_md: Path) -> list:
    d = skill_md.parent
    text = skill_md.read_text(encoding="utf-8", errors="replace")
    fm = _front_matter(text)
    errs = []
    if not fm:
        return ["SKILL.md 缺 front matter"]
    m = _NAME_RE.search(fm)
    if not m:
        return ["SKILL.md front matter 缺 name"]
    name = _clean(m.group(1))
    if name != d.name:
        errs.append(f"name({name}) 与目录名({d.name}) 不一致")
    return errs


def discover(manifest: dict):
    assets = manifest.get("assets", {})
    agents = sorted(ROOT.glob(assets.get("agents", "agents/*.md")))
    roles = sorted(ROOT.glob(assets.get("roles", "roles/*.yaml")))
    skills = sorted(ROOT.glob(assets.get("skills", "skills/*/SKILL.md")))
    return agents, roles, skills


def collect_files(manifest: dict, agents, roles, skills, personality: Path) -> list:
    files = [(MANIFEST, "manifest.json"), (personality, "SOUL.md")]
    for p in agents:
        files.append((p, f"agents/{p.name}"))
    for p in roles:
        files.append((p, f"roles/{p.name}"))
    for skill_md in skills:
        d = skill_md.parent
        for f in sorted(d.rglob("*")):
            if f.is_file():
                files.append((f, f"skills/{d.name}/{f.relative_to(d).as_posix()}"))
    return files


def main() -> int:
    ap = argparse.ArgumentParser(description="SecAutoMind 工作区打包（P3）")
    ap.add_argument("--check", action="store_true", help="只校验，不出包")
    ap.add_argument("--list", action="store_true", help="列出将纳入的文件")
    ap.add_argument("--out", default=None, help="输出路径（默认 dist/secautomind-workspace-<ver>.tar.gz）")
    args = ap.parse_args()

    if not MANIFEST.exists():
        print(f"[FAIL] 清单缺失: {MANIFEST}", file=sys.stderr)
        return 2
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001 - 任何解析错误都按配置错误处理
        print(f"[FAIL] 清单解析失败: {e}", file=sys.stderr)
        return 2

    agents, roles, skills = discover(manifest)
    errs = []
    for p in agents:
        for e in validate_agent(p):
            errs.append(f"{p.relative_to(ROOT)}: {e}")
    for p in roles:
        for e in validate_role(p):
            errs.append(f"{p.relative_to(ROOT)}: {e}")
    for p in skills:
        for e in validate_skill(p):
            errs.append(f"{p.relative_to(ROOT)}: {e}")

    print(f"发现资产：agents={len(agents)} roles={len(roles)} skills={len(skills)}")
    if errs:
        print(f"[FAIL] 资产校验失败 {len(errs)} 处：")
        for e in errs:
            print("  -", e)
        return 1
    print("[PASS] 资产校验通过")

    personality = WS / manifest.get("personality", "SOUL.md")
    if not personality.exists():
        print(f"[FAIL] 人格文件缺失: {personality}", file=sys.stderr)
        return 1

    if args.check:
        return 0

    files = collect_files(manifest, agents, roles, skills, personality)

    if args.list:
        for _, arc in files:
            print(arc)
        return 0

    version = manifest.get("version", "0.0.0")
    out = Path(args.out) if args.out else ROOT / "dist" / f"secautomind-workspace-{version}.tar.gz"
    out.parent.mkdir(parents=True, exist_ok=True)

    with tarfile.open(out, "w:gz") as tf:
        for src, arc in sorted(files, key=lambda x: x[1]):
            ti = tf.gettarinfo(str(src), arcname=arc)
            ti.mtime = 0
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            with open(src, "rb") as fh:
                tf.addfile(ti, fh)

    print(f"[OK] 已产出 {out}（{out.stat().st_size} 字节，{len(files)} 文件）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
