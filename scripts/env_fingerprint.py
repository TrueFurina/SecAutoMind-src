#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""env_fingerprint.py — 实验/基准产物的环境指纹块（REA #33 / #239）

为什么必须有：一份"准确率 62%"的结果，缺环境指纹就等于不可复现。三个月后
没人知道它跑在哪个 Python、哪个 commit、哪套依赖上；一旦数字对不上，
排查会从"代码改坏了"开始，而真实原因通常是"换了解释器/依赖小版本"。

本模块只做一件事：产出一个**可写进结果文件**的 dict，字段固定、无路径泄漏：

    {
      "python": "3.13.12",
      "implementation": "CPython",
      "platform": "Windows-11-10.0.22631-SP0",
      "machine": "AMD64",
      "git_head": "abc1234",          # 短 SHA；仓库不可用时为 null
      "git_dirty": true,              # 工作区是否脏（脏 = 结果不可精确复现）
      "deps": {"pyyaml": "6.0.1", ...},   # 只记已安装的关键包版本
      "seeds": {...},                 # 由调用方传入
      "captured_at": "2026-10-20T12:00:00+00:00"
    }

纪律：
  * **不写绝对路径**（公开仓库不暴露本机目录结构）；
  * **不写环境变量原值**（可能含密钥）；只允许写"哪些变量被设置过"的 SHA256 指纹；
  * 取不到的项写 `null` 并记入 `unknown`，**不编默认值**——"未检查"不等于"没问题"。
"""
from __future__ import annotations

import hashlib
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone

# 关键依赖：基准/评测结果会受它们影响；缺了就记 null（而不是跳过该项）
_WATCHED_DEPS = ("pyyaml", "requests", "numpy", "pandas", "openai", "httpx")

# 允许记录"是否设置过"的环境变量（值本身不进结果，只进指纹）
_WATCHED_ENV = ("CUDA_VISIBLE_DEVICES", "OMP_NUM_THREADS", "PYTHONHASHSEED", "TZ")

#: 清单文件白名单：**按精确文件名/模式**匹配，不认识的文件名不猜（REA #239）。
#: 遍历时按深度剪枝，避免把 node_modules 里几万份 package.json 算成本项目依赖。
_MANIFEST_MAX_DEPTH = 3
#: 但"算进依赖集"的清单只认仓库根与其**直接**子目录（如 py-server/pyproject.toml）。
#: 更深层多半是归档的提交包/子项目（实测 Security-Agent_融合/submission/… 下就有一份
#: requirements.txt），把它们并进来会让指纹混入与本项目无关的包。
_DECLARED_MAX_DEPTH = 1
_PRUNE_DIRS = {".git", ".workbuddy", "node_modules", ".venv", "venv", "dist",
               "build", "vendor", "site-packages", "__pycache__", ".mypy_cache",
               "installer", "chat_uploads", "workspace"}



def _git(args: list[str], cwd: str | None = None) -> str | None:
    try:
        out = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                             timeout=10)
        return out.stdout.strip() if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def git_state(cwd: str | None = None) -> dict:
    """仓库状态：短 HEAD + 是否脏。非 git 目录返回 null（不猜）。"""
    head = _git(["rev-parse", "--short", "HEAD"], cwd)
    status = _git(["status", "--porcelain"], cwd)
    return {
        "git_head": head,
        "git_dirty": (bool(status) if status is not None else None),
    }


def _default_root() -> "os.PathLike | None":
    """默认仓库根 = 本文件的上上级（scripts/ 的父目录）。"""
    from pathlib import Path
    return Path(__file__).resolve().parent.parent


def _classify_manifest(name: str) -> "tuple[str, str] | None":
    """按精确文件名/模式判定 (生态, 角色)；不认识返回 None（不猜）。

    角色只有两种：`manifest`（宽松声明）/ `lock`（精确锁定）。
    区分二者是本盘点最有用的信号——**有声明没锁定 = 装出来的环境不可复现**。
    """
    low = name.lower()
    if low == "go.mod":
        return ("go", "manifest")
    if low == "go.sum":
        return ("go", "lock")
    if low == "package.json":
        return ("node", "manifest")
    if low in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb"):
        return ("node", "lock")
    if low == "pyproject.toml":
        return ("python", "manifest")
    if low in ("setup.py", "setup.cfg", "pipfile"):
        return ("python", "manifest")
    if low in ("poetry.lock", "uv.lock", "pipfile.lock"):
        return ("python", "lock")
    if low.startswith("requirements") and low.endswith(".txt"):
        # requirements.txt / requirements-dev.txt → manifest
        # requirements.lock.txt / requirements-lock.txt → lock
        return ("python", "lock" if "lock" in low else "manifest")
    if low == "cargo.toml":
        return ("rust", "manifest")
    if low == "cargo.lock":
        return ("rust", "lock")
    return None


def manifest_inventory(root=None) -> dict:
    """依赖清单盘点（REA #239）：仓库里**有哪些**声明/锁定文件，各自字节指纹。

    产物随基准结果公开，故只写**仓库相对路径**（posix 风格）、不写绝对路径。

    三项判断都是"能救回一个坏结果"的：
      * `files` —— 事后核对"当时锁的是哪一版"，靠 hash 而不是靠记忆；
      * `ecosystems_without_lock` —— 有声明没锁定 ⇒ 重装可能装出别的版本；
      * `scanned` —— 扫描根与是否找全，避免"没扫到"被读成"没有依赖"。
    """
    from pathlib import Path

    base = Path(root) if root is not None else _default_root()
    files: list[dict] = []
    ecosystems: dict[str, set[str]] = {}
    if base is None or not base.is_dir():
        return {"scanned": False, "root_relative": True, "files": [],
                "ecosystems": {}, "ecosystems_without_lock": [],
                "note": "仓库根不存在，无法盘点（未检查 ≠ 没有依赖）"}

    base = base.resolve()
    for cur, dirs, names in os.walk(base):
        depth = len(Path(cur).relative_to(base).parts)
        if depth >= _MANIFEST_MAX_DEPTH:
            dirs[:] = []
        dirs[:] = sorted(d for d in dirs if d not in _PRUNE_DIRS)
        for name in sorted(names):
            kind = _classify_manifest(name)
            if kind is None:
                continue
            eco, role = kind
            path = Path(cur) / name
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            files.append({
                "path": path.relative_to(base).as_posix(),
                "ecosystem": eco,
                "role": role,
                "depth": depth,
                "sha256": hashlib.sha256(raw).hexdigest()[:16],
                "size_bytes": len(raw),
            })
            ecosystems.setdefault(eco, set()).add(role)
    files.sort(key=lambda f: (f["ecosystem"], f["path"]))
    return {
        "scanned": True,
        "root_relative": True,
        "files": files,
        "ecosystems": {k: sorted(v) for k, v in sorted(ecosystems.items())},
        "ecosystems_without_lock": sorted(e for e, roles in ecosystems.items()
                                          if "lock" not in roles),
    }


def _normalize_dist(name: str) -> str:
    """PEP 503 归一化：`Foo_Bar.Baz` → `foo-bar-baz`（跨清单/元数据比对的前提）。"""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


#: requirements 行首的包名（PEP 508 的 name 部分；extras/marker 由后续字符自然截断）
_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


def _parse_requirements(text: str) -> dict[str, str]:
    """解析 requirements*.txt：返回 {归一化名: 原始行}。

    只做"提取包名"这一件事，故按下列规则跳过而非报错：
      * `#` 注释、空行；
      * 以 `-` 开头的选项行（`-r` / `-e` / `--index-url`）；
      * 含 `://` 或 `git+` 的 VCS/URL 行（包名无法从源码 URL 静态判定）。
    这些情况**不假装解析成功**，但也无法静态审计——属本函数的已知盲区。
    """
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        if "://" in line or line.lower().startswith("git+"):
            continue
        m = _REQ_NAME_RE.match(line)
        if m:
            out.setdefault(_normalize_dist(m.group(1)), line)
    return out


def _parse_pyproject(text: str) -> "tuple[dict[str, str], str | None]":
    """解析 pyproject.toml 的依赖名（PEP 621 + poetry 两种写法）。

    返回 (声明集合, 未解析原因)。**解析不了必须说出来**：study-help-pro 的
    python 清单就只有 pyproject.toml，若这里静默返回空集，`declared_count`
    会显示 0 —— 读起来像"这项目没有 python 依赖"，实际是"脚本没读它"。
    """
    try:
        import tomllib
    except Exception:                                  # pragma: no cover
        return {}, "当前 Python 无 tomllib（<3.11），pyproject.toml 未解析"
    try:
        doc = tomllib.loads(text)
    except Exception as exc:
        return {}, f"TOML 解析失败：{exc}"

    specs: list[str] = []
    project = doc.get("project")
    if isinstance(project, dict):
        # PEP 621：dependencies 是 PEP 508 字符串列表（如 "httpx[http2]>=0.27"）
        v = project.get("dependencies")
        if isinstance(v, list):
            specs += [s for s in v if isinstance(s, str)]
        opt = project.get("optional-dependencies")
        if isinstance(opt, dict):
            for v in opt.values():
                if isinstance(v, list):
                    specs += [s for s in v if isinstance(s, str)]
    tool = doc.get("tool") if isinstance(doc.get("tool"), dict) else None
    poetry = (tool or {}).get("poetry")
    if isinstance(poetry, dict):
        # poetry：dependencies 是 表名 → 说明（字符串或表），键即包名；`python` 是版本约束
        for name in (poetry.get("dependencies") or {}):
            if isinstance(name, str) and name != "python":
                specs.append(name)
        for group in (poetry.get("group") or {}).values():
            if isinstance(group, dict):
                for name in (group.get("dependencies") or {}):
                    if isinstance(name, str) and name != "python":
                        specs.append(name)
    if not specs:
        return {}, "未找到 [project.dependencies] / [tool.poetry.dependencies]，无可静态提取的依赖名"
    out: dict[str, str] = {}
    for s in specs:
        m = _REQ_NAME_RE.match(s.strip())
        if m:
            out.setdefault(_normalize_dist(m.group(1)), s.strip())
    return out, (None if out else "依赖条目无法提取包名")


def _declared_manifest_paths(base) -> list[dict]:
    """参与"依赖集"的 python 清单（depth ≤ _DECLARED_MAX_DEPTH）。"""
    return [f for f in manifest_inventory(base)["files"]
            if f["ecosystem"] == "python"
            and f["depth"] <= _DECLARED_MAX_DEPTH
            and (f["path"].split("/")[-1].startswith("requirements")
                 or f["path"].split("/")[-1] == "pyproject.toml")]


def declared_python_deps(root=None) -> dict[str, str]:
    """仓库内 requirements*.txt 声明的 Python 依赖（归一化名 → 原始行）。

    只认 depth ≤ `_DECLARED_MAX_DEPTH` 的清单（根与直接子目录）——更深的
    requirements 多半属于归档的提交包，并进指纹会让"这份结果依赖什么"失真。
    """
    from pathlib import Path

    base = Path(root) if root is not None else _default_root()
    out: dict[str, str] = {}
    if base is None or not base.is_dir():
        return out
    for f in _declared_manifest_paths(base):
        base_name = f["path"].split("/")[-1]
        try:
            text = (Path(base) / f["path"]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if base_name == "pyproject.toml":
            got, _reason = _parse_pyproject(text)
        else:
            got = _parse_requirements(text)
        for k, v in got.items():
            out.setdefault(k, v)
    return out


def unparsed_manifests(root=None) -> list[dict]:
    """参与依赖集但**没解析出任何依赖名**的清单 —— 逐条给出原因。

    这条是给"declared_count = 0"兜底的：0 既可能是"确实没依赖"，也可能是
    "清单读不懂"。不区分这两者，指纹就成了装样子的字段。
    """
    from pathlib import Path

    base = Path(root) if root is not None else _default_root()
    out: list[dict] = []
    if base is None or not base.is_dir():
        return out
    for f in _declared_manifest_paths(base):
        base_name = f["path"].split("/")[-1]
        try:
            text = (Path(base) / f["path"]).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            out.append({"path": f["path"], "reason": f"读不出：{exc}"})
            continue
        if base_name == "pyproject.toml":
            _got, reason = _parse_pyproject(text)
        else:
            got = _parse_requirements(text)
            reason = None if got else "文件里没有可静态提取的依赖名（仅注释/选项行？）"
        if reason:
            out.append({"path": f["path"], "reason": reason})
    return out


def declared_source_files(root=None) -> list[str]:
    """喂给 `declared_python_deps` 的清单文件清单（让读者能自己核）。"""
    from pathlib import Path

    base = Path(root) if root is not None else _default_root()
    if base is None or not base.is_dir():
        return []
    return sorted(f["path"] for f in _declared_manifest_paths(base))


def deps(root=None) -> dict:
    """依赖版本。未安装 = null（不省略键，便于跨结果对比）。

    键集合 = `_WATCHED_DEPS` ∪ 仓库 `requirements*.txt` 实际声明的包。
    早先只有固定白名单：清单里新增一个会决定结果的依赖，指纹不会变——正是
    "环境指纹看着齐全、其实漏掉关键项"的经典形态。改为从清单生长后，新增依赖
    自动进入指纹；未装的自动进 `unknown`。
    """
    from importlib import metadata

    names = list(_WATCHED_DEPS)
    seen = {_normalize_dist(n) for n in names}
    for name in sorted(declared_python_deps(root)):
        if name not in seen:
            names.append(name)
            seen.add(name)
    out: dict[str, str | None] = {}
    for name in names:
        try:
            out[name] = metadata.version(name)
        except Exception:      # PackageNotFoundError 等
            out[name] = None
    return out


def deps_coverage(root=None) -> dict:
    """声明 / 已安装 / 声明了却没装 的三段式对账（REA #239）。

    `declared_not_installed` 非空不代表代码坏了，它代表**这份结果装不出宣称赞同
    的那套依赖**——复现者照 requirements 装完，仍可能与产出结果的机器不同。
    """
    declared = declared_python_deps(root)
    resolved = deps(root)
    missing = sorted(n for n in declared if resolved.get(n) is None)
    where = sampling_context(root)
    note = None
    if missing and not where["sampled_in_project_venv"]:
        # 2026-10-21 实测事故：study-help-pro 用托管 venv 采集时报
        # "32 声明 / 25 已装、langgraph 未装"，换项目自带 py-server/.venv
        # 重采后是 32/32（全装）。缺口来自**采样环境不对**，不是依赖缺失。
        note = ("以下 declared_not_installed 由**非本项目**解释器采集，"
                "很可能是采样环境不对而非依赖缺失；"
                "请用目标项目自己的 venv 重采后再下结论。")
    return {
        "declared_count": len(declared),
        "watched_count": len(_WATCHED_DEPS),
        "installed_count": sum(1 for v in resolved.values() if v is not None),
        "declared_not_installed": missing,
        "declared_from": declared_source_files(root),
        "unparsed_manifests": unparsed_manifests(root),
        "sampling": where,
        "sampling_warning": note,
    }


def sampling_context(root=None) -> dict:
    """这次指纹是**用哪个解释器**采的？说不清就别拿它判"缺依赖"。

    不写可执行文件的绝对路径（含用户名，且要随产物公开），只回答两个是非题：
    ① 当前是否在 venv 里；② 该 venv 是否属于被采集的仓库。
    """
    import sys

    try:
        in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    except Exception:      # pragma: no cover
        in_venv = False
    owns = False
    if root and in_venv:
        try:
            from pathlib import Path

            owns = str(Path(sys.prefix).resolve()).lower().startswith(
                str(Path(root).resolve()).lower())
        except Exception:  # pragma: no cover
            owns = False
    return {
        "in_venv": in_venv,
        "sampled_in_project_venv": bool(in_venv and owns),
    }



def env_hashes() -> dict:
    """环境变量**是否设置**的指纹（不含值）。设置过 = sha256(名字+值)[:12]。"""
    out: dict[str, str | None] = {}
    for name in _WATCHED_ENV:
        raw = os.environ.get(name)
        out[name] = (hashlib.sha256(f"{name}={raw}".encode("utf-8")).hexdigest()[:12]
                     if raw is not None else None)
    return out


def collect(cwd: str | None = None, seeds: dict | None = None,
            root=None) -> dict:
    """组装指纹。`unknown` 列出取不到的项——下游据此判断可信度，不要静默。

    `cwd` 只影响 git 状态（调用方常在别的目录里跑）；`root` 决定从哪个仓库
    盘点依赖清单，默认本文件所在仓库——两者故意分开：用 cwd 去盘清单，
    在 CI 里会盘出"零份清单"，而那是假象。
    """
    data = {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        **git_state(cwd),
        "deps": deps(root),
        "deps_manifest": manifest_inventory(root),
        "deps_coverage": deps_coverage(root),
        "env_fingerprints": env_hashes(),
        "seeds": seeds or {},
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    unknown = [k for k, v in data.items() if v is None]
    unknown += [f"deps.{k}" for k, v in data["deps"].items() if v is None]
    if not data["deps_manifest"]["scanned"]:
        unknown.append("deps_manifest.scanned")
    data["unknown"] = sorted(unknown)
    return data


def stamp(payload: dict, cwd: str | None = None, seeds: dict | None = None,
          root=None) -> dict:
    """就地写入 `env` 字段并返回 payload（调用方少写一行）。"""
    payload["env"] = collect(cwd=cwd, seeds=seeds, root=root)
    return payload


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(description="打印当前环境指纹（JSON）")
    ap.add_argument("--cwd", default=None, help="git 状态取自哪个目录（默认当前目录）")
    ap.add_argument("--root", default=None,
                    help="依赖清单盘点哪个仓库根（默认本脚本所在仓库；"
                         "盘点别的仓库时用它，别用 --cwd——cwd 只管 git）")
    args = ap.parse_args(argv)
    print(json.dumps(collect(cwd=args.cwd, root=args.root), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
