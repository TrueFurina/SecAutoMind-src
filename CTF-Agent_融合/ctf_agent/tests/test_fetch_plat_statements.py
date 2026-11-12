"""fetch_plat_statements 的解析逻辑回归（不触网）。

fixture 取自本机真实缓存 platform_archive/meta/10663.json 的字段形态。
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.fetch_plat_statements import extract_flag_pattern, normalize  # noqa: E402

# 真实缓存里的题面（10663：「解压缩」）
_DESC_10663 = "解压获取福来阁，快来试试吧，flag格式为DASCTF{}。"


def test_pattern_from_chinese_phrase():
    assert extract_flag_pattern(_DESC_10663) == r"DASCTF\{.*\}"


def test_pattern_generic_flag_braces():
    assert extract_flag_pattern("直接找 flag{...} 即可") == r"flag\{.*\}"


def test_pattern_absent_returns_none():
    assert extract_flag_pattern("本题没有给出格式提示") is None
    assert extract_flag_pattern("") is None


def test_normalize_keeps_no_answer():
    detail = {
        "id": "10663", "name": "解压缩", "description": _DESC_10663,
        "score": "50.0", "difficulty": "VERY_EASY",
        "attachment": [{"name": "解压缩的附件.zip",
                        "url": "https://example.invalid/x.zip"}],
    }
    q = normalize(detail, "10663")
    assert q["id"] == "10663"
    assert q["flag_pattern"] == r"DASCTF\{.*\}"
    assert q["attachments"] == ["解压缩的附件.zip"]
    # 关键：平台不返回答案，这里必须是空的——否则会被当成离线可判分
    assert q["flag"] == ""
    assert q["flag_sha256"] == ""
    assert q["_source"] == "ctf2.platform"


def test_normalize_files_field_variant():
    # 详情接口文档写的字段是 files，缓存里叫 attachment，两种都要吃
    detail = {"description": "flag格式为DASCTF{}", "files": [{"name": "a.zip"}],
              "category": "Crypto", "difficulty": "HARD"}
    q = normalize(detail, "10733")
    assert q["attachments"] == ["a.zip"]
    assert q["category"] == "crypto"
    json.dumps(q, ensure_ascii=False)  # 必须可序列化


def test_normalize_unknown_category_falls_back():
    q = normalize({"description": "x", "category": ""}, "10999")
    assert q["category"] == "misc"
    assert q["flag_pattern"] == ""
