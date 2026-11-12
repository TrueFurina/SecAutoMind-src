"""锁死 math_engine._engine_high_exponent 的取字段顺序（2026-11-13 服务器实跑回归）。

为什么单独写一个测试：
`tests/test_10733_high_exponent_route.py` 只测到 **skill 层**
（crypto_high_exponent.run 返回的 flag 命中 sha256），而 bug 在 **engine 层**
—— math_engine 从 skill 结果里挑哪个字段返回。旧代码按 ('rot18','rot13','flag')
取，优先 rot18；10733 的规范 flag 是 ROT13（数字不动），rot18 把数字 +5，
于是 presolve 明明解出来了、sha256 却必然不符而被丢弃，实跑表现为
FLAG None / wrong_direction。skill 层测试对这个 bug 完全不敏感，所以修前
3 passed 也照样漏。

本测试做双向断言：
1. engine 返回的值必须命中 10733 题面真值 sha256（正）；
2. skill 的 rot18 候选必须**不**命中（变异/反证）——若哪天有人把顺序改回
   rot18 优先，断言 1 立刻变红；而断言 2 证明「rot18 确实是错的解码」，
   避免有人以「两个都像 flag」为理由把顺序再翻回去。
"""
import hashlib
import importlib.util
import json
import os
import re
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
Q10733_JSON = os.path.join(_HERE, "..", "data", "questions_real", "crypto", "10733.json")
TASK_PY = os.path.join(
    _HERE, "..", "data", "race_attachments",
    "10733_How_many_rot_are_there的附件", "tempdir", "CRYPTO附件", "task.py")


def _sha(v):
    return hashlib.sha256(str(v).encode("utf-8")).hexdigest()


def _load_che():
    spec = importlib.util.spec_from_file_location(
        "crypto_high_exponent",
        os.path.join(_HERE, "..", "skills", "crypto_high_exponent.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _numbers():
    with open(TASK_PY, encoding="utf-8") as f:
        block = re.search(r"'''(.*?)'''", f.read(), re.S).group(1)
    v = {m.group(1): int(m.group(2))
         for m in re.finditer(r"(n|hint|c|p|q)\s*=\s*(\d+)", block)}
    return v["n"], 65536, v["c"], v["hint"]


class _Q:
    """最小 Question 替身：engine 只读 category / attachments。"""

    category = "crypto"

    def __init__(self, attachments):
        self.attachments = attachments


def _truth():
    with open(Q10733_JSON, encoding="utf-8") as f:
        return json.load(f)["flag_sha256"]


class TestEngineFieldOrder(unittest.TestCase):
    @unittest.skipUnless(os.path.exists(TASK_PY), "10733 附件不在本机（干净检出会跳过）")
    def test_engine_result_hits_truth_sha256(self):
        """engine 走真实 task.py，返回的 flag 必须命中题面真值。"""
        from agents.math_engine import _engine_high_exponent
        got = _engine_high_exponent(_Q([TASK_PY]))
        self.assertIsNotNone(got, "engine 未返回候选 —— 嗅探或 skill 链路坏了")
        self.assertEqual(_sha(got), _truth(),
                         "engine 返回的候选未命中 10733 真值 sha256（疑似又把 rot18 优先了）")

    @unittest.skipUnless(os.path.exists(TASK_PY), "10733 附件不在本机（干净检出会跳过）")
    def test_rot18_candidate_does_not_hit_truth(self):
        """反证：skill 的 rot18 字段必须**不**命中真值——它是错解码。"""
        che = _load_che()
        n, e, c, hint = _numbers()
        res = che.run({"n": n, "e": e, "c": c, "hint": hint, "kind": "auto"})
        self.assertTrue(res.get("ok"), "skill 未解出")
        rot18 = res.get("rot18")
        self.assertTrue(rot18, "skill 应同时给出 rot18 候选（用于反证）")
        self.assertNotEqual(_sha(rot18), _truth(),
                            "rot18 竟然命中真值 —— 那本题的 rot 判定前提变了，需重新核对")

    def test_source_order_is_flag_first(self):
        """静态锁：取值顺序必须是 flag -> rot13 -> rot18。"""
        src_path = os.path.join(_HERE, "..", "agents", "math_engine.py")
        with open(src_path, encoding="utf-8") as f:
            src = f.read()
        self.assertIn('for key in ("flag", "rot13", "rot18")', src,
                      "math_engine 取字段顺序不是 flag 优先，10733 会再次解不出")
        self.assertNotIn('for key in ("rot18", "rot13", "flag")', src,
                         "math_engine 又改回 rot18 优先了")


if __name__ == "__main__":
    unittest.main(verbosity=2)
