"""check_ci_pytest_deselect 的变异自测：注入违例必须变红。

为什么必须有本文件（AGENTS.md 第四条）：门禁自身要有回归测试，关键门禁还要有
**变异验证**——不注入错误就无法证明"测试有效"。失效的门禁比没有门禁更危险，
它会持续给出假的安全感。

本文件对三种腐化各做一次注入，并额外验证"改坏就不通过"的因果方向：
  ① 膨胀（超过上限）
  ② 悬空（节点改名后仍留在清单里）
  ③ 无因（缺 root_cause / reason 过短）

跑法：python scripts/check_ci_pytest_deselect_test.py
退出码：0 全过 / 1 有用例失败
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
GATE = HERE / "check_ci_pytest_deselect.py"


def _run(ledger_obj: dict) -> tuple:
    """把给定清单写到临时文件，让门禁读它，返回 (rc, stdout)。"""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "_ci_pytest_deselect.json"
        p.write_text(json.dumps(ledger_obj, ensure_ascii=False), encoding="utf-8")
        r = subprocess.run(
            [sys.executable, str(GATE), "--ledger", str(p)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        return r.returncode, (r.stdout or "") + (r.stderr or "")


def _base() -> dict:
    return json.loads((HERE / "_ci_pytest_deselect.json").read_text(encoding="utf-8"))


def test_clean_ledger_passes():
    rc, out = _run(_base())
    assert rc == 0, out


def test_inflation_rejected():
    """① 膨胀：条目数超上限必须红。"""
    led = _base()
    led["entries"] = led["entries"] * 3          # 42 > 20
    rc, out = _run(led)
    assert rc == 1, f"超上限应判红，实际 rc={rc}: {out}"
    assert "膨胀" in out, out


def test_dangling_node_rejected():
    """② 悬空：节点改名后仍在清单里，--deselect 会静默匹配不到 → 必须红。"""
    led = _base()
    led["entries"][0]["node"] = (
        "tests/test_doc_consistency.py::test_this_function_was_renamed_and_is_gone")
    rc, out = _run(led)
    assert rc == 1, f"悬空条目应判红，实际 rc={rc}: {out}"
    assert "悬空" in out, out


def test_missing_root_cause_rejected():
    """③ 无因：缺 root_cause 必须红（下一个人无法判断能否恢复）。"""
    led = _base()
    led["entries"][0].pop("root_cause", None)
    rc, out = _run(led)
    assert rc == 1, f"缺 root_cause 应判红，实际 rc={rc}: {out}"
    assert "root_cause" in out, out


def test_short_reason_rejected():
    """③' 无因变体：reason 写空话也必须红。"""
    led = _base()
    led["entries"][0]["reason"] = "暂时跳过"
    rc, out = _run(led)
    assert rc == 1, f"reason 过短应判红，实际 rc={rc}: {out}"
    assert "过短" in out, out


def test_marker_drift_rejected():
    """口径漂移：ledger 的 marker_expr 与 pytest.ini 不一致必须红。"""
    led = _base()
    led["marker_expr"] = "not slow"
    rc, out = _run(led)
    assert rc == 1, f"口径漂移应判红，实际 rc={rc}: {out}"


def test_returns_2_when_ledger_missing():
    """fail-closed：取不到清单不能算通过。"""
    r = subprocess.run([sys.executable, str(GATE), "--ledger", "D:/__nope__.json"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert r.returncode == 2, f"缺清单应返回 2，实际 {r.returncode}: {r.stdout}{r.stderr}"


def main() -> int:
    tests = [
        test_clean_ledger_passes,
        test_inflation_rejected,
        test_dangling_node_rejected,
        test_missing_root_cause_rejected,
        test_short_reason_rejected,
        test_marker_drift_rejected,
        test_returns_2_when_ledger_missing,
    ]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"✅ {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"❌ {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} 通过")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
