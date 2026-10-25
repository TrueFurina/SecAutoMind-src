# -*- coding: utf-8 -*-
"""把生成器源码里**内联**的 CTF flag 明文外置到 gitignore 的真值文件。

为什么不能像 `redact_plaintext_flags.py` 那样直接遮蔽成 `前缀{****}`：
生成器要用 flag 明文做真值（算 sha256、编码进工件）。遮蔽会让它产出
`picoCTF{****}` 这种假值 —— 产物静默变错，比明文泄露更危险。

正确姿势：明文搬到 gitignore 的本地真值文件，源码改为运行时读取，
**真值缺失必须 fail-closed 报错**（不是静默产出残缺基准集）。

用法：
    python scripts/externalize_generator_flags.py            # 预演
    python scripts/externalize_generator_flags.py --apply     # 落盘
    python scripts/externalize_generator_flags.py --selftest  # 自测
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 自测夹具：**拼接构造**，源码里不留完整 `前缀{正文}` 字面量 —— 否则本仓自己的
# 明文 flag 门禁（secret_guard 冻结上限）会把测试文件当新泄露而打红。
_FIXTURE_A = "ctfdemo" + "{" + "aaa_bbb}"
_FIXTURE_B = "ctfdemo" + "{" + "ccc}"

# id → flag 的抽取：以 `{"id":"xxx"` 分块，块内找 "flag":"yyy"
BLOCK_RE = re.compile(r'\{"id":"([^"]+)"(.*?)(?=\n\s*\{"id":"|\n\])', re.S)
FLAG_RE = re.compile(r'"flag"\s*:\s*"((?:[^"\\]|\\.)*)"\s*,?')

TARGET = "data/ctf_benchmark/build_real_benchmark.py"
TRUTH_REL = "data/answers/build_real_benchmark_answers.json"

# 注入到源码的读取逻辑（真值缺失 = fail-closed）
LOADER = '''
# ── 真值外置（红线：flag 明文不得入 PUBLIC 仓）────────────────────────
# 明文答案存于 gitignore 的 data/answers/，源码只留 id。缺失时 fail-closed：
# 宁可构建失败，也不产出 flag_sha256 缺失/错误的残缺基准集。
def _load_flag_truth(path='%s'):
    import os
    if not os.path.isfile(path):
        raise SystemExit(
            '[build] 缺少真值文件 %%s —— flag 明文按红线不入 PUBLIC 仓。\\n'
            '        本机真值由 scripts/externalize_generator_flags.py 生成；\\n'
            '        换机需从赛题原始来源重建，或向维护者索取。' %% path)
    with open(path, encoding='utf-8') as f:
        return json.load(open(path, encoding='utf-8')).get('answers', {})


_FLAG_TRUTH = _load_flag_truth()
''' % TRUTH_REL

BACKFILL = """

# 回填：按 id 从真值文件取明文 flag（源码内已无明文）
for _it in real:
    _v = _FLAG_TRUTH.get(_it.get('id', ''))
    if not _v:
        raise SystemExit('[build] 真值文件缺少 id=%s 的 flag' % _it.get('id'))
    _it['flag'] = _v
"""


def extract(text: str):
    """返回 (新文本, {id: flag}, 命中条数)。新文本已删除内联的 "flag":"..." 片段。"""
    truth: dict[str, str] = {}
    n = 0
    out = text

    def _sub(m: "re.Match[str]") -> str:
        nonlocal n
        pid = m.group(1)
        body = m.group(2)
        fm = FLAG_RE.search(body)
        if not fm:
            return m.group(0)
        flag_val = fm.group(1)
        truth[pid] = flag_val
        n += 1
        # 删除该块内的 "flag":"..." 片段（连同尾逗号），保留其余结构
        new_body = body[:fm.start()] + body[fm.end():]
        return '{"id":"%s"%s' % (pid, new_body)

    out = BLOCK_RE.sub(_sub, out)
    return out, truth, n


def inject(text: str) -> str:
    """在 real 列表定义前插入加载器，在列表结束后插入回填。"""
    if "_FLAG_TRUTH" in text:
        return text  # 已注入，幂等
    # 1) 加载器：插在 "real = [" 之前
    idx = text.find("real = [")
    if idx < 0:
        raise SystemExit("找不到 `real = [`，注入中止")
    text = text[:idx] + LOADER.lstrip("\n") + text[idx:]
    # 2) 回填：插在 real 列表结束的 "] " 之后
    end = text.find("\n]\n", text.find("real = ["))
    if end < 0:
        raise SystemExit("找不到 real 列表结尾，注入中止")
    cut = end + len("\n]\n")
    return text[:cut] + BACKFILL + text[cut:]


def run(apply: bool, as_json: bool) -> int:
    src = ROOT / TARGET
    text = src.read_text(encoding="utf-8")
    new_text, truth, n = extract(text)
    if not n:
        print(f"未找到内联 flag（{TARGET}）—— 可能已外置，或结构变了需核对正则")
        return 0
    new_text = inject(new_text)
    out = {
        "target": TARGET,
        "extracted": n,
        "truth_file": TRUTH_REL,
        "mode": "apply" if apply else "dry-run",
    }
    if apply:
        src.write_text(new_text, encoding="utf-8")
        tpath = ROOT / TRUTH_REL
        tpath.parent.mkdir(parents=True, exist_ok=True)
        tpath.write_text(json.dumps(
            {"_note": "明文答案（gitignore，禁止入 PUBLIC 仓/交付包）",
             "answers": truth}, ensure_ascii=False, indent=1) + "\n",
            encoding="utf-8")
        # 真值目录必须 gitignore —— 否则外置等于没做（脚本注释早就声称"不入库"却没加规则）
        gi = ROOT / ".gitignore"
        cur = gi.read_text(encoding="utf-8") if gi.is_file() else ""
        line = "data/answers/"
        if line not in cur:
            gi.write_text(cur.rstrip("\n") + f"\n# CTF 明文答案（红线：禁止入 PUBLIC 仓）\n{line}\n",
                          encoding="utf-8")
            print(f"✅ .gitignore 已加入 {line}")
        print(f"✅ 已外置 {n} 条明文 → {TRUTH_REL}（源码内已无明文）")
    else:
        if as_json:
            print(json.dumps(out, ensure_ascii=False, indent=1))
        else:
            print(f"== 预演（未写盘）==  将从 {TARGET} 外置 {n} 条内联明文 → {TRUTH_REL}")
            print("   落盘：python scripts/externalize_generator_flags.py --apply")
    return 0


class TestSelf(unittest.TestCase):
    def _sample(self):
        return (
            'import json\n\nreal = [\n'
            '    {"id":"a1","category":"crypto","sub":"x","difficulty":"easy",\n'
            '     "source":"S1","flag":"' + _FIXTURE_A + '","description":"d1"},\n'
            '    {"id":"b2","category":"misc","difficulty":"easy",\n'
            '     "source":"S2","flag":"' + _FIXTURE_B + '","description":"d2"},\n'
            ']\n'
        )

    def test_extract_removes_flag_and_keeps_id(self):
        new, truth, n = extract(self._sample())
        self.assertEqual(n, 2)
        self.assertEqual(truth, {"a1": _FIXTURE_A, "b2": _FIXTURE_B})
        self.assertNotIn(_FIXTURE_A, new)
        self.assertNotIn("ctfdemo{ccc}", new)
        # 结构保留
        self.assertIn('"id":"a1"', new)
        self.assertIn('"description":"d1"', new)
        self.assertIn("real = [", new)

    def test_inject_is_idempotent_and_has_fail_closed(self):
        new, _, _ = extract(self._sample())
        once = inject(new)
        self.assertIn("_FLAG_TRUTH", once)
        self.assertIn("raise SystemExit", once)  # fail-closed，不静默
        self.assertEqual(inject(once), once, "重复注入必须幂等")

    def test_injected_source_is_executable(self):
        """端到端：注入后的源码必须能跑通，且真值缺失时 fail-closed 退出。"""
        new, truth, _ = extract(self._sample())
        src = inject(new)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data" / "answers").mkdir(parents=True)
            tf = root / TRUTH_REL
            tf.write_text(json.dumps({"answers": truth}, ensure_ascii=False),
                          encoding="utf-8")
            (root / "m.py").write_text(src, encoding="utf-8")
            import subprocess
            r = subprocess.run([sys.executable, "-c",
                                "import json,os;os.chdir(r'%s');"
                                "exec(open('m.py',encoding='utf-8').read());"
                                "print(json.dumps([i['flag'] for i in real]))"
                                % str(root).replace("\\", "/")],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(json.loads(r.stdout.strip().splitlines()[-1]),
                             [_FIXTURE_A, _FIXTURE_B],
                             "回填后 flag 必须与真值一致")
            # 真值缺失 → 必须非零退出（fail-closed）
            tf.unlink()
            r2 = subprocess.run([sys.executable, "-c",
                                 "import os;os.chdir(r'%s');"
                                 "exec(open('m.py',encoding='utf-8').read())"
                                 % str(root).replace("\\", "/")],
                                capture_output=True, text=True, encoding="utf-8",
                                errors="replace")
            self.assertNotEqual(r2.returncode, 0, "真值缺失必须 fail-closed")


def selftest() -> int:
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSelf)
    r = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if r.wasSuccessful() else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    sys.exit(selftest() if a.selftest else run(a.apply, a.json))
