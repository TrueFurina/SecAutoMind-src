#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""CI 自测入口：能力率判据链 + 私有性外部锚点契约的变异验证。

项目约定：CI job 的自测入口用 `*_test.py`（门禁地图据此标注「有变异/自测」）。
这里只做转发，不新增判据；两段都是合成数据，不产出可引用分数。

  python scripts/capability_caliber_test.py
退出码：两段全绿 = 0；任一失败 = 1。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import audit_private_proof  # noqa: E402
import run_capability_eval  # noqa: E402


def main() -> int:
    print("=== 1/2 私有性外部锚点契约（含洗白攻击变异）===")
    rc1 = audit_private_proof.selftest()
    print("=== 2/2 能力率判据链路（判据/入口/作用域/假阴性）===")
    rc2 = run_capability_eval.pipeline_selftest()
    ok = (rc1 == 0 and rc2 == 0)
    print("能力率口径门禁自测：%s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
