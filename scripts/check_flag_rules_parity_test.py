#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`check_flag_rules_parity.py` 的回归测试。

判别力要求（否则就是装饰）：
  - 真实仓库必须绿（基线）
  - Go 多一个词 / Py 多一个词 / 正则改一个字符 / 分隔符少一个 → **必须红**
  - Go 源码被改名、文件消失 → **必须红**（fail-closed，不许「解析失败=没问题」）
  - 命令行 --check 在漂移时真的 exit 1
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_flag_rules_parity as C  # noqa: E402


def go_src(pattern: str, words, seps=("_", "-", " ", ".")) -> str:
    """按 Go 源码的真实形状拼一段文本，供解析测试用（不依赖仓库文件）。"""
    word_lines = "\n".join(f'\t"{w}": true,' for w in sorted(words))
    sep_expr = " || ".join(f"r == '{s}'" for s in seps)
    return (
        "package ctfplatform\n\n"
        "import \"regexp\"\n\n"
        f"var flagPlaceholderRe = regexp.MustCompile(`{pattern}`)\n\n"
        "var flagPlaceholderWords = map[string]bool{\n"
        f"{word_lines}\n"
        "}\n\n"
        "func isLowInformationContent(s string) bool {\n"
        "\tdistinct := map[rune]bool{}\n"
        "\tfor _, r := range s {\n"
        f"\t\tif {sep_expr} {{\n"
        "\t\t\tcontinue\n"
        "\t\t}\n"
        "\t\tdistinct[r] = true\n"
        "\t}\n"
        "\treturn len(distinct) == 1\n"
        "}\n"
    )


FIXTURE_WORDS = {"flag", "test", "example", "placeholder", "filler"}
FIXTURE_PATTERN = r"(?i)(\binit\d+\b|x{4,}|\.\.\.|\byour|\*{4,}|%[a-z]|\?{2,})"


def write_go(td, src):
    p = Path(td) / C.GO_REL
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return str(td)


class TestParse(unittest.TestCase):
    def test_parses_three_artifacts(self):
        go = C.parse_go_rules(go_src(FIXTURE_PATTERN, FIXTURE_WORDS))
        self.assertEqual(go["words"], FIXTURE_WORDS)
        self.assertEqual(go["separators"], {"_", "-", " ", "."})
        self.assertEqual(go["pattern"], FIXTURE_PATTERN)

    def test_missing_regex_raises(self):
        src = go_src(FIXTURE_PATTERN, FIXTURE_WORDS).replace("flagPlaceholderRe", "renamedVar")
        with self.assertRaises(ValueError):
            C.parse_go_rules(src)

    def test_missing_words_map_raises(self):
        src = go_src(FIXTURE_PATTERN, FIXTURE_WORDS).replace("flagPlaceholderWords", "otherMap")
        with self.assertRaises(ValueError):
            C.parse_go_rules(src)

    def test_missing_low_info_fn_raises(self):
        src = go_src(FIXTURE_PATTERN, FIXTURE_WORDS).replace(
            "isLowInformationContent", "somethingElse")
        with self.assertRaises(ValueError):
            C.parse_go_rules(src)

    def test_empty_word_map_raises(self):
        """格式变了但没解析出错（0 个词）也必须当失败，不能「比了个空集」就绿。"""
        with self.assertRaises(ValueError):
            C.parse_go_rules(go_src(FIXTURE_PATTERN, set()))


class TestCompare(unittest.TestCase):
    """纯函数比对：每一项都必须真的有判别力。"""

    def setUp(self):
        self.go = C.parse_go_rules(go_src(FIXTURE_PATTERN, FIXTURE_WORDS))

    def test_consistent_gives_no_violation(self):
        v = C.compare(self.go, FIXTURE_PATTERN, FIXTURE_WORDS, {"_", "-", " ", "."})
        self.assertEqual(v, [])

    def test_go_extra_word_detected(self):
        go = dict(self.go, words=set(FIXTURE_WORDS) | {"newjunk"})
        v = C.compare(go, FIXTURE_PATTERN, FIXTURE_WORDS, {"_", "-", " ", "."})
        self.assertTrue(any("newjunk" in x for x in v), v)

    def test_py_extra_word_detected(self):
        """本轮实锤：Python 侧自造了 Go 里没有的 `demo`。"""
        v = C.compare(self.go, FIXTURE_PATTERN, set(FIXTURE_WORDS) | {"demo"},
                      {"_", "-", " ", "."})
        self.assertTrue(any("demo" in x for x in v), v)

    def test_py_missing_word_detected(self):
        """本轮实锤：Python 侧漏抄 7 个词。"""
        v = C.compare(self.go, FIXTURE_PATTERN, set(FIXTURE_WORDS) - {"filler"},
                      {"_", "-", " ", "."})
        self.assertTrue(any("filler" in x for x in v), v)

    def test_pattern_drift_detected(self):
        v = C.compare(self.go, FIXTURE_PATTERN.replace(r"\?{2,}", ""),
                      FIXTURE_WORDS, {"_", "-", " ", "."})
        self.assertTrue(any("正则不一致" in x for x in v), v)

    def test_separator_drift_detected(self):
        v = C.compare(self.go, FIXTURE_PATTERN, FIXTURE_WORDS, {"_", "-", " "})
        self.assertTrue(any("分隔符" in x for x in v), v)


class TestCheckFailClosed(unittest.TestCase):
    def test_missing_go_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            v, _ = C.check(td)
            self.assertTrue(v, "Go 源码不存在时必须报红，不许静默放过")
            self.assertIn("读不到", v[0])

    def test_unparseable_go_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            write_go(td, "package ctfplatform\n// 判据被整体删掉了\n")
            v, _ = C.check(td)
            self.assertTrue(v, "判据解析不到时必须报红")
            self.assertIn("fail-closed", v[0])

    def test_drift_makes_check_exit_1(self):
        """命令行层：漂移必须真的 exit 1（光返回列表不算门禁）。"""
        with tempfile.TemporaryDirectory() as td:
            write_go(td, go_src(FIXTURE_PATTERN, FIXTURE_WORDS | {"extra_guy"}))
            self.assertEqual(C.main(["--check", "--repo-root", td]), 1,
                             "Go 多一个词，--check 必须 exit 1")

    def test_consistent_fixture_exits_0(self):
        """夹具与 Python 侧逐字一致时必须 exit 0 —— 防判据恒红（恒红等于没有门禁）。"""
        sg = C._load_py_side()
        with tempfile.TemporaryDirectory() as td:
            write_go(td, go_src(sg.PLACEHOLDER_BODY_RE.pattern,
                                set(sg.PLACEHOLDER_WORDS),
                                tuple(sorted(C.PY_LOW_INFO_SEPARATORS))))
            self.assertEqual(C.main(["--check", "--repo-root", td]), 0,
                             "与 Python 侧一致却报红 = 门禁恒红")


class TestRealRepo(unittest.TestCase):
    def test_repo_is_consistent(self):
        """本仓库当前必须一致（漂移了 CI 立刻红，正是设计意图）。"""
        violations, detail = C.check(C.REPO_ROOT)
        self.assertEqual(violations, [], f"判据漂移: {violations}")
        self.assertEqual(detail["n_go_words"], detail["n_py_words"])

    def test_gate_in_ci(self):
        """门禁必须接进 CI —— 没接 CI 的门禁等于没锁（AGENTS 第四条）。"""
        ci = Path(C.REPO_ROOT) / ".github" / "workflows" / "ci.yml"
        self.assertTrue(ci.is_file(), "找不到 ci.yml")
        self.assertIn("check_flag_rules_parity", ci.read_text(encoding="utf-8"),
                      "check_flag_rules_parity 未接进 CI")


if __name__ == "__main__":
    unittest.main(verbosity=2)
