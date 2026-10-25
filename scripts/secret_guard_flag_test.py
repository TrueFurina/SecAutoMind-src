#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""明文 CTF flag 门禁的回归 + 变异测试（事故 #20）。

为什么单独一个文件：secret_guard_test.py 是自带 harness 的钥匙串门禁自测，
判据与失败语义不同；flag 门禁有独立的「精度 / 分诊策略 / 端到端防新增」三段断言，
混进去会互相污染。CI 两处都要跑。

三条不可退化的能力：
  1. 精度：真 flag 必须命中，Go 结构体字面量 / 占位符必须**不**命中
     （误报洪水会让门禁被当噪音关掉 —— 实测未收紧前噪声占 59%）。
  2. 分诊：未入库副本不阻断、已入库超冻结上限必须阻断、非 git 空目录不得假红。
  3. 端到端：冻结基线后，**新加入库的含 flag 文件必须让门禁 rc=1**。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
GUARD = SCRIPTS / "secret_guard.py"


def _mk(prefix: str, body: str) -> str:
    """拼接构造测试夹具：源码里不留完整的 `前缀{正文}` 字面量。

    这不是洁癖 —— 本仓自己就开着明文 flag 门禁（冻结上限只许减不许增），
    测试文件里写完整字面量会被自己判成"新泄露"，一提交就把门禁打红。
    拼接后正则扫不到，而传给被测函数的仍是完整字符串，判据强度不变。
    """
    return prefix + "{" + body + "}"


def _load_guard():
    import importlib.util
    spec = importlib.util.spec_from_file_location("sg_flag", GUARD)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _hits_in(tmpdir: Path, files: dict[str, str]):
    """在临时目录写文件，返回 flag 命中列表（tracked 一律按未跟踪处理）。"""
    sg = _load_guard()
    for name, content in files.items():
        p = tmpdir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    hits, untracked = sg.scan_plaintext_flags(str(tmpdir), set())
    return hits, untracked


class TestPrecision(unittest.TestCase):
    """判据精度：真 flag 命中，代码噪声不命中。"""

    def test_real_flags_are_detected(self):
        with tempfile.TemporaryDirectory() as td:
            # 夹具约束：只保留「品牌前缀 + 花括号」的形状用于测分类，
            # body 一律写成 selftest_*，不得抄真题 flag 正文（PUBLIC 仓红线）。
            hits, _ = _hits_in(Path(td), {
                "a.txt": _mk("flag", "selftest_generic_body") + "\n",
                "b.txt": _mk("VNCTF", "selftest-uuid-shape-0000") + "\n",
                "c.txt": _mk("picoCTF", "selftest_body_not_real") + "\n",
                "d.txt": _mk("DASCTF", "init1-init2") + "\n",
            })
            self.assertEqual(len(hits), 4, f"4 条真 flag 必须全部命中，实际 {hits}")

    def test_flag_with_single_quote_is_detected(self):
        """真 flag 里出现过单引号（c4n'7）—— 收紧噪声时不得把它一起禁掉。"""
        with tempfile.TemporaryDirectory() as td:
            hits, _ = _hits_in(Path(td), {
                "a.txt": _mk("flag", "selftest_quote'body") + "\n",
            })
            self.assertEqual(len(hits), 1, hits)

    def test_long_flag_body_is_detected(self):
        """真答案 body 可超过 80 字符。

        2026-10-25 实锤：heldout_evidence 里有条 90 字符的真答案被旧正则的
        `{4,80}` 上限整条漏掉 —— 外形通道抽不到，后面的 sha256 命中通道就
        无从谈起，两条防线同时失效。**漏报比误报危险**：误报还能人工筛。
        """
        body = "selftest_" + "abcdefghij" * 9  # 99 字符，且不含占位符特征
        with tempfile.TemporaryDirectory() as td:
            hits, _ = _hits_in(Path(td), {"a.txt": _mk("flag", body) + "\n"})
            self.assertEqual(len(hits), 1, f"长 body 真 flag 未命中: {hits}")

    def test_flag_body_with_comma_is_detected(self):
        """真答案 body 可含逗号（同夜实锤：含逗号的答案被旧字符类整条漏掉）。

        夹具纪律：用虚构的 `11,22,33`，**不抄真答案正文**。
        """
        with tempfile.TemporaryDirectory() as td:
            hits, _ = _hits_in(Path(td), {"a.txt": _mk("flag", "11,22,33") + "\n"})
            self.assertEqual(len(hits), 1, f"含逗号真 flag 未命中: {hits}")

    def test_go_struct_literals_are_not_flags(self):
        """Go 结构体字面量是最大的噪声源（实测占 59%），必须不命中。"""
        with tempfile.TemporaryDirectory() as td:
            hits, _ = _hits_in(Path(td), {
                "a.go": 'x := ExecuteRequest{Command: cmd}\n'
                        'y := string{"xxe", "xml外部实体"}\n'
                        'z := Message{schema.ToolMessage("hi", "", w)}\n'
                        'c := countResult{name: n, count: -1}\n',
            })
            self.assertEqual(hits, [], f"Go 结构体字面量被误判为 flag: {hits}")

    def test_placeholders_are_not_flags(self):
        with tempfile.TemporaryDirectory() as td:
            hits, _ = _hits_in(Path(td), {
                "a.txt": "flag{****}\npicoCTF{xxxx}\nflag{...}\n",
            })
            self.assertEqual(hits, [], hits)

    def test_finditer_over_findall(self):
        """纪律：正则带捕获组，必须用 finditer + group(0)，findall 恒绿。"""
        src = GUARD.read_text(encoding="utf-8")
        self.assertIn("finditer", src)
        self.assertNotIn("FLAG_CAND_RE.findall", src)


class TestPolicy(unittest.TestCase):
    """分诊策略：不阻断未入库副本，只卡已入库的新增。"""

    def _eval(self, hits, tracked_set, baseline):
        return _load_guard().evaluate_flag_policy(hits, tracked_set, baseline)

    def test_no_git_no_hits_passes(self):
        """非 git 的干净目录不得假红（打穿过 --allow-no-fingerprint 放行语义）。"""
        block, note, _, _ = self._eval([], None, None)
        self.assertFalse(block, note)

    def test_no_git_with_hits_blocks(self):
        block, note, _, _ = self._eval(
            [{"file": "a", "line": 1, "masked": "flag{**}", "tracked": False}],
            None, None)
        self.assertTrue(block, note)

    def test_no_baseline_warns(self):
        block, note, _, _ = self._eval(
            [{"file": "a", "line": 1, "masked": "flag{**}", "tracked": True}],
            {"a"}, None)
        self.assertFalse(block, "无基线时应告警而非阻断（避免新判据一上就把 CI 打红）")
        self.assertIn("无冻结基线", note)

    def test_over_cap_blocks(self):
        hits = [{"file": "a", "line": 1, "masked": "flag{**}", "tracked": True}]
        block, note, _, _ = self._eval(hits, {"a"}, {"tracked_hits": 0})
        self.assertTrue(block, note)
        self.assertIn("冻结上限", note)

    def test_at_cap_passes(self):
        hits = [{"file": "a", "line": 1, "masked": "flag{**}", "tracked": True}]
        block, note, n, _ = self._eval(hits, {"a"}, {"tracked_hits": 1})
        self.assertFalse(block, note)
        self.assertEqual(n, 1)

    def test_untracked_copies_do_not_block(self):
        """未入库副本不进 PUBLIC 仓，不计入上限，也不阻断。"""
        hits = [{"file": "copy", "line": 1, "masked": "flag{**}", "tracked": False}]
        block, note, n, untracked = self._eval(hits, set(), {"tracked_hits": 0})
        self.assertFalse(block, note)
        self.assertEqual(n, 0)
        self.assertEqual(len(untracked), 1)

    # ── 真赛事品牌独立卡口（堵「总数不变」的洗白通道）──────────────────
    def test_real_brand_over_cap_blocks_even_if_total_under_cap(self):
        """删掉 5 条自产夹具、换进 5 条真题答案 → 总数不变，必须仍拦。

        这是只卡总数时的真实漏洞：清理动作让总数下降，顺手塞真题答案进来，
        总数仍 ≤ 上限，门禁全绿，而真题答案已经进了 PUBLIC 仓。
        """
        hits = [
            {"file": "a", "line": 1, "masked": "flag{**}", "tracked": True, "brand": "self"},
            {"file": "a", "line": 2, "masked": "flag{**}", "tracked": True, "brand": "self"},
            {"file": "b", "line": 3, "masked": "DASCTF{**}", "tracked": True, "brand": "real"},
        ]
        # 总数 3 ≤ 上限 10，但真品牌 1 > 上限 0
        block, note, _, _ = self._eval(
            hits, {"a", "b"}, {"tracked_hits": 10, "real_brand_hits": 0})
        self.assertTrue(block, note)
        self.assertIn("真题答案", note)

    def test_real_brand_at_cap_passes(self):
        hits = [{"file": "b", "line": 3, "masked": "DASCTF{**}", "tracked": True,
                 "brand": "real"}]
        block, note, n, _ = self._eval(
            hits, {"b"}, {"tracked_hits": 5, "real_brand_hits": 1})
        self.assertFalse(block, note)
        self.assertEqual(n, 1)

    def test_old_baseline_without_real_key_still_passes(self):
        """旧基线没有 real_brand_hits 键 → 不阻断（否则一升级就把 CI 打红）。"""
        hits = [{"file": "b", "line": 3, "masked": "DASCTF{**}", "tracked": True,
                 "brand": "real"}]
        block, note, _, _ = self._eval(hits, {"b"}, {"tracked_hits": 5})
        self.assertFalse(block, note)
        self.assertIn("未记真品牌上限", note)


class TestKnownAnswerCap(unittest.TestCase):
    """铁实锤卡口：唯一可机验的判据是「sha256 命中题库真值」。

    这一档存在的理由（2026-10-25 实测）：前两个卡口都能被换料洗白 ——
    总数靠「删夹具 + 加答案」平账，真品牌靠改前缀（`DASCTF{真答案}` → `flag{真答案}`）
    直接从 real 档消失。只有哈希改不了，所以它单独成口。
    """

    SHA = "a" * 64

    def _eval(self, hits, baseline, truth=None):
        return _load_guard().evaluate_flag_policy(hits, {"a"}, baseline, truth=truth)

    def _hit(self, brand="self", sha=None):
        return {"file": "a", "line": 1, "masked": "flag{**}", "tracked": True,
                "brand": brand, "sha256": sha or self.SHA}

    def test_changed_prefix_does_not_hide_known_answer(self):
        """把真题答案的前缀改成 `flag{}` 不得逃过铁实锤卡口。

        首版按 `brand == "real"` 过滤，实测把 HEAD 上 987 条 `flag{真答案}` 全归进
        「自产构造」，真泄露队列只剩 157 条 —— 少报 6 倍。改前缀是零成本伪装，
        判据必须落在哈希上。
        """
        block, note, _, _ = self._eval(
            [self._hit(brand="self")],
            {"tracked_hits": 10, "real_brand_hits": 10, "known_answer_hits": 0},
            truth={self.SHA})
        self.assertTrue(block, note)
        self.assertIn("铁实锤", note)

    def test_real_brand_unknown_hash_is_not_known_answer(self):
        """外形像真题、哈希对不上真值 → 不算铁实锤（陷阱假 flag 就长这样）。"""
        block, note, _, _ = self._eval(
            [self._hit(brand="real", sha="b" * 64)],
            {"tracked_hits": 10, "real_brand_hits": 10, "known_answer_hits": 0},
            truth={self.SHA})
        self.assertFalse(block, note)

    def test_known_answer_at_cap_passes(self):
        block, note, _, _ = self._eval(
            [self._hit()],
            {"tracked_hits": 10, "real_brand_hits": 10, "known_answer_hits": 1},
            truth={self.SHA})
        self.assertFalse(block, note)
        self.assertIn("铁实锤真题答案 1 条", note)

    def test_placeholder_hash_is_not_promoted(self):
        """占位符即使哈希躺在真值集里也不算答案（题库有这类脏数据）。"""
        block, note, _, _ = self._eval(
            [self._hit(brand="placeholder")],
            {"tracked_hits": 10, "real_brand_hits": 10, "known_answer_hits": 0},
            truth={self.SHA})
        self.assertFalse(block, note)

    def test_no_truth_says_skipped_not_passed(self):
        """没有真值集时必须明说「卡口跳过」，不能静默显示通过。"""
        block, note, _, _ = self._eval(
            [self._hit()], {"tracked_hits": 10, "known_answer_hits": 0})
        self.assertFalse(block, note)
        self.assertIn("跳过", note)


class TestBrandClassification(unittest.TestCase):
    """品牌分诊：占位符模板不是答案，不得计进「真赛事品牌真泄露」队列。

    动机（2026-10-25 实测）：此前 `brand` 只分 real/self，`DASCTF{%d-%d}`
    （printf 模板）、`DASCTF{init1-init2}`（题面格式声明）、`picoCTF{your_flag_here}`
    这些**不含答案**的串全被算成「真泄露」，161 条里 53 条是假阳性（虚报 33%），
    把真正要清的 108 条稀释掉了。判据与 internal/ctfplatform/presolve_registry.go
    的 flagPlaceholderRe / flagPlaceholderWords 同构 —— 引擎已判「不是 flag」的串，
    门禁不能还报「真泄露」。
    """

    def _cls(self, raw):
        return _load_guard().classify_brand(raw)

    def test_printf_templates_are_placeholders(self):
        for raw in ("DASCTF{%d-%d}", "DASCTF{uid_%d}", "DASCTF{%s}"):
            self.assertEqual(self._cls(raw), "placeholder", raw)

    def test_format_declarations_are_placeholders(self):
        for raw in ("DASCTF{init1-init2}", "picoCTF{your_flag_here}",
                    "flag{****}", "picoCTF{xxxx}", "flag{...}"):
            self.assertEqual(self._cls(raw), "placeholder", raw)

    def test_truncated_samples_are_placeholders(self):
        """文档里的截断样例（`DASCTF{3792...}`）不含完整答案，不是泄露。"""
        self.assertEqual(self._cls("DASCTF{3792...}"), "placeholder")

    def test_placeholder_words_are_placeholders(self):
        for raw in ("DASCTF{test}", "picoCTF{example}", "flag{sample}"):
            self.assertEqual(self._cls(raw), "placeholder", raw)

    def test_real_brand_answer_is_real(self):
        """正文是真答案（非占位形态）时必须仍判 real —— 别把判据放宽成恒假。"""
        for raw in ("DASCTF{selftest_abc123}", "picoCTF{selftest_body}"):
            self.assertEqual(self._cls(raw), "real", raw)

    def test_generic_brand_is_self(self):
        self.assertEqual(self._cls("flag{selftest_body}"), "self")

    def test_placeholder_does_not_consume_real_brand_quota(self):
        """占位符不能挤占真品牌配额：真品牌 0 条 + 占位符 5 条 → 不得拦。"""
        hits = [{"file": "d", "line": i, "masked": "DASCTF{**}",
                 "tracked": True, "brand": "placeholder"} for i in range(5)]
        block, note, n, _ = _load_guard().evaluate_flag_policy(
            hits, {"d"}, {"tracked_hits": 10, "real_brand_hits": 0})
        self.assertFalse(block, note)
        self.assertEqual(n, 5)
        self.assertIn("占位符模板 5 条", note)


class TestTrackedEncoding(unittest.TestCase):
    """非 ASCII 路径的入库判定（2026-10-25 实测缺陷）。"""

    def _git(self, cwd, *args):
        return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                               "-c", "commit.gpgsign=false", *args],
                              cwd=cwd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace")

    def test_non_ascii_path_counts_as_tracked(self):
        """`git ls-files` 默认把非 ASCII 路径转义成带引号的八进制串。

        不修的话 `rel in tracked` 永远为 False —— 整个 `CTF-Agent_融合/`
        （本仓 153 个 skill + core/presolve.py）被当成"未入库副本"，
        既漏判真泄露，又让"未入库 N 条"虚高到失真。
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._git(root, "init", "-q")
            sub = root / "融合仓" / "skills"
            sub.mkdir(parents=True)
            (sub / "a.py").write_text(_mk("flag", "non_ascii_path_body") + "\n",
                                      encoding="utf-8")
            r = self._git(root, "add", "-A")
            self.assertEqual(r.returncode, 0, r.stderr)

            guard = _load_guard()
            tracked = guard._git_tracked(str(root))
            self.assertIsNotNone(tracked)
            self.assertIn("融合仓/skills/a.py", tracked,
                          f"非 ASCII 路径没进 tracked：{sorted(tracked)}")
            hits, untracked = guard.scan_plaintext_flags(str(root), tracked)
            self.assertEqual(len(hits), 1, hits)
            self.assertTrue(hits[0]["tracked"], "非 ASCII 路径必须被识别为已入库")
            self.assertEqual(untracked, [])


class TestEndToEnd(unittest.TestCase):
    """端到端：冻结基线后，新加入库的含 flag 文件必须让门禁 rc=1。"""

    def _git(self, cwd, *args):
        return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                               "-C", str(cwd)] + list(args),
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=60)

    def _run_guard(self, cwd, baseline_path, *extra):
        env = dict(os.environ)
        env["SECRET_GUARD_FLAG_BASELINE"] = str(baseline_path)
        return subprocess.run([sys.executable, str(GUARD), "--dir", str(cwd),
                               "--allow-no-fingerprint"] + list(extra),
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=120, env=env)

    def test_new_tracked_flag_file_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"
            root.mkdir()
            base = Path(td) / "baseline.json"
            self.assertEqual(self._git(root, "init").returncode, 0)
            (root / "clean.txt").write_text("nothing here\n", encoding="utf-8")
            self._git(root, "add", "clean.txt")
            self.assertEqual(self._git(root, "commit", "-m", "init").returncode, 0)

            # 冻结：干净状态 = 0 条
            r = self._run_guard(root, base, "--freeze-flag-baseline")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            data = json.loads(base.read_text(encoding="utf-8"))
            self.assertEqual(data["tracked_hits"], 0)

            # 新增未入库文件：不阻断（还没进 git）
            (root / "leak.txt").write_text(_mk("flag", "TEST_ONLY_NEVER_REAL") + "\n",
                                           encoding="utf-8")
            r2 = self._run_guard(root, base)
            self.assertEqual(r2.returncode, 0,
                             "未入库文件不该阻断（不进 PUBLIC 仓）：" + r2.stdout)

            # git add 之后 = 入库泄露，必须阻断
            self._git(root, "add", "leak.txt")
            r3 = self._run_guard(root, base)
            self.assertEqual(r3.returncode, 1,
                             "新加入库的明文 flag 必须让门禁 rc=1：" + r3.stdout[-1500:])
            self.assertIn("冻结上限", r3.stdout)

    def test_freeze_refuses_to_raise_cap(self):
        """重冻只许降不许升 —— 否则「上限」就是可随时刷新的装饰品。

        真实风险不是误判：往仓里加 100 条 flag，再重冻一次，历史责任就从账面上
        消失了。所以上调必须显式 `--allow-raise --reason`，且理由写进基线。
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"
            root.mkdir()
            base = Path(td) / "baseline.json"
            self.assertEqual(self._git(root, "init").returncode, 0)
            (root / "a.txt").write_text(_mk("flag", "FIRST_ONLY") + "\n", encoding="utf-8")
            self._git(root, "add", "a.txt")
            self.assertEqual(self._git(root, "commit", "-m", "a").returncode, 0)
            r = self._run_guard(root, base, "--freeze-flag-baseline")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(json.loads(base.read_text(encoding="utf-8"))["tracked_hits"], 1)

            # 加第二条明文后再冻结：不得静默调高
            (root / "b.txt").write_text(_mk("flag", "SECOND_ONLY") + "\n", encoding="utf-8")
            self._git(root, "add", "b.txt")
            self.assertEqual(self._git(root, "commit", "-m", "b").returncode, 0)
            r2 = self._run_guard(root, base, "--freeze-flag-baseline")
            self.assertEqual(r2.returncode, 1, "上调必须被拒绝：" + r2.stdout[-800:])
            self.assertIn("只许降不许升", r2.stdout)
            self.assertEqual(json.loads(base.read_text(encoding="utf-8"))["tracked_hits"], 1,
                             "被拒绝时不得改动基线")

            # 显式承认后放行，且理由落盘
            r3 = self._run_guard(root, base, "--freeze-flag-baseline",
                                 "--allow-raise", "--reason", "新增了一条必要夹具")
            self.assertEqual(r3.returncode, 0, r3.stdout + r3.stderr)
            data = json.loads(base.read_text(encoding="utf-8"))
            self.assertEqual(data["tracked_hits"], 2)
            self.assertIn("新增了一条必要夹具", data["_frozen_basis"])

    def test_baseline_is_not_polluted(self):
        """回归测试必须通过环境变量隔离基线，绝不能**改动**真基线文件。

        首版断言的是「真基线文件不存在」——人工冻结后该前提过期（基线本就该存在），
        于是假红。正确语义是「跑完测试后内容不变」：既能防污染，又不与人工冻结冲突。
        """
        self.assertTrue("SECRET_GUARD_FLAG_BASELINE" in GUARD.read_text(encoding="utf-8"))
        real = SCRIPTS / "plaintext_flag_baseline.json"
        if not real.is_file():
            return  # 尚未冻结：本轮无法判定污染，跳过而非假红
        before = real.read_text(encoding="utf-8")
        # 在临时仓库上跑一次完整 guard（基线走环境变量隔离），再验真基线未被改动
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"
            root.mkdir()
            (root / "clean.txt").write_text("nothing here\n", encoding="utf-8")
            self._run_guard(root, Path(td) / "isolated_baseline.json")
        self.assertEqual(real.read_text(encoding="utf-8"), before,
                         "测试运行改动了真基线文件（污染）")


if __name__ == "__main__":
    unittest.main(verbosity=2)
