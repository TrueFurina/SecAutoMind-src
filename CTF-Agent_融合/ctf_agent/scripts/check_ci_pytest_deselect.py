#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CTF-Agent 全量 pytest 门禁的自测（2026-10-31）。

守什么
------
`pytest.ini` 早就定义了正式门禁口径 `-m "not slow and not local"`，`scripts/_ci_local.sh`
也实现了它，但它**从未接进 `.github/workflows/ci.yml`** —— 2212 个用例全靠人记得跑。

接 CI 时实测：该口径下有 **14 个用例必然红**，且全部来自同一个根因：
本目录 `CTF-Agent_融合/` 是**迁移副本**，不是完整仓库 ——
  · `README.md` 被改写成 33 行迁移说明（原项目的 break-ice 段落 / 计数声明都没迁入）；
  · `data/` 整目录被 `.gitignore` 排除（manifest 载荷、canonical 真值、附件都不在）。

这些用例原样跟着代码过来，它们的**前提**却没了。直接接 CI = 一道永久红的门禁，
而永久红门禁的结局就是被人整段注释掉（`scripts/_gate_coverage.py` 头部原话：
「设一个够不到的目标只会得到一道天天红、然后被整段注释掉的闸门」）。

处置 = 精确 deselect 这 14 条（**记账，不是删除**），并让本自测守住清单不腐化。

为什么必须自测（而不是"清单写对就行了"）
--------------------------------------
deselect 清单的腐化有三种，且全部**静默**：
  ① **膨胀**：以后遇到红就往上加一条 → 门禁实际覆盖范围逐月缩小，没人看得见；
  ② **悬空**：被排除的用例日后改名/删除 → `--deselect` 匹配不到会**静默跳过**，
     清单看着还在，实际已经不管任何东西（假绿）；
  ③ **无因**：只写节点不写原因 → 下一个人无法判断能不能恢复，只能永远留着。
本文件对三种各设一条断言，并做变异验证（故意注入违例必须变红）。

退出码：0 通过 / 1 违规 / 2 无法判定
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent                      # ctf_agent/
LEDGER = HERE / "_ci_pytest_deselect.json"
TESTS_DIR = ROOT / "tests"

# 豁免条目数量上限：**故意压低**。这是「记账额度」而不是「配额」——
# 想加必须删旧或修根因，逼着人面对问题，而不是把红一条条划掉。
MAX_ENTRIES = 20


def load(path: "Path | None" = None) -> dict:
    return json.loads((path or LEDGER).read_text(encoding="utf-8"))


def check_structure(ledger: dict) -> list:
    """每条必须有 node + reason，reason 不得是占位符。"""
    problems = []
    for i, e in enumerate(ledger.get("entries", [])):
        node = (e.get("node") or "").strip()
        reason = (e.get("reason") or "").strip()
        if not node:
            problems.append(f"第 {i} 条缺 node")
        if not re.match(r"^tests/[A-Za-z0-9_./\[\]-]+\.py::", node):
            problems.append(f"{node!r} 不是合法的 pytest 节点 id")
        # 原因必须能解释「为什么这是迁移副本的结构性缺失」，不是"暂时跳过"这类空话
        if len(reason) < 20:
            problems.append(f"{node}: reason 过短（{len(reason)} 字符），无法判断能否恢复")
        if e.get("root_cause") not in ("readme_not_migrated", "data_dir_gitignored",
                                       "aggregate_of_above"):
            problems.append(f"{node}: root_cause 非法或缺失")
    return problems


def check_cap(ledger: dict) -> list:
    n = len(ledger.get("entries", []))
    if n > MAX_ENTRIES:
        return [f"deselect 清单膨胀：{n} 条 > 上限 {MAX_ENTRIES}。"
                f"豁免是记账额度不是配额——要么修根因，要么删旧条目。"]
    return []


def check_nodes_exist(ledger: dict) -> list:
    """悬空检测：节点必须仍能在当前 tests/ 里找到同名函数。

    pytest 的 `--deselect` 匹配不到时**静默不报错**，所以改名后清单会变成
    「看着还在、其实不管任何东西」——这是最隐蔽的一种假绿。
    """
    problems = []
    for e in ledger.get("entries", []):
        node = e.get("node") or ""
        file_part, _, rest = node.partition("::")
        if not rest:
            continue
        fname = file_part.split("/")[-1]
        fpath = TESTS_DIR / fname
        if not fpath.is_file():
            problems.append(f"{node}: 测试文件已不存在（{fname}）→ 悬空条目")
            continue
        # 末段方法名（兼容 Class::method 与 func[param]）
        leaf = rest.split("::")[-1]
        leaf = re.sub(r"\[.*\]$", "", leaf)
        if leaf not in fpath.read_text(encoding="utf-8", errors="ignore"):
            problems.append(f"{node}: 函数 {leaf!r} 在 {fname} 中找不到 → 悬空条目")
    return problems


def check_consistent_with_ini(ledger: dict) -> list:
    """口径必须与 pytest.ini 声称的默认门禁一致（marker 表达式不许各说各的）。

    ⚠️ 2026-10-31 变异自测抓到过本函数的一版 bug：原先用 `want in text` 判子串，
    于是 `marker_expr="not slow"` 能在 `"not slow and not local"` 里命中 → 漏判。
    "not slow" 比 "not slow and not local" 宽得多（会多跑 local 用例，CI 上必红），
    这正是要防的漂移。改为**按行精确比对**。
    """
    problems = []
    ini = ROOT / "pytest.ini"
    if not ini.is_file():
        return ["pytest.ini 缺失，无法校验门禁口径"]
    text = ini.read_text(encoding="utf-8", errors="ignore")
    want = ledger.get("marker_expr", "")
    if not want:
        return ["ledger 缺 marker_expr"]
    # pytest.ini 里的声明形如：  ;  默认门禁（setup.sh / CI 用）：pytest -q -m "not slow and not local"
    # 精确要求：带上引号的完整表达式出现过。
    if f'"{want}"' not in text:
        problems.append(
            f"ledger 的 marker_expr={want!r} 未以完整引号形式出现在 pytest.ini 中——"
            f"说明两者口径漂移，CI 与本地跑的不是同一批用例")
    return problems


def main(argv: "list | None" = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="deselect 记账表自检")
    # --ledger 供变异自测注入坏清单；生产 CI 不传，用默认路径。
    ap.add_argument("--ledger", default=str(LEDGER),
                    help="清单路径（默认 scripts/_ci_pytest_deselect.json）")
    args = ap.parse_args(argv)

    path = Path(args.ledger)
    if not path.is_file():
        print(f"❌ 缺清单：{path}")
        return 2
    try:
        ledger = load(path)
    except (OSError, json.JSONDecodeError) as e:
        print(f"❌ 清单不可解析：{e}")
        return 2

    problems = []
    problems += check_structure(ledger)
    problems += check_cap(ledger)
    problems += check_nodes_exist(ledger)
    problems += check_consistent_with_ini(ledger)

    if problems:
        print("❌ deselect 清单自检未通过：")
        for p in problems:
            print("   -", p)
        return 1

    n = len(ledger["entries"])
    print(f"✅ deselect 清单自检通过：{n} 条（上限 {MAX_ENTRIES}），"
          f"全部有 root_cause、节点均存活、口径与 pytest.ini 一致")
    return 0


if __name__ == "__main__":
    sys.exit(main())
