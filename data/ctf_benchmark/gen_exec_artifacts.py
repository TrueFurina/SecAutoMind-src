#!/usr/bin/env python3
"""
生成执行基准集工件 + execution_benchmark.json。

每个工件都是自包含、可机验的真实 CTF 挑战数据；求解器真正调用
strings / git / tshark(纯Python等价) / curl 等工具提取 flag，
对齐 flag_sha256。覆盖维度：二进制 strings、源码 base64、免密 cookie、
git 历史泄露、小端序、HTTP pcap 取证。

运行：python data/ctf_benchmark/gen_exec_artifacts.py
"""
import json
import os
import base64
import struct
import subprocess
import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
EXEC_DIR = os.path.join(HERE, "execution")
os.makedirs(EXEC_DIR, exist_ok=True)


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


FLAGS = {
    "exec_strings": "flag{str1ngs_r3v34l5_5ecret5}",
    "exec_base64_source": "flag{v13w_50urc3_70_f1nd}",
    "exec_cookie": "flag{c00k13_c4n_h1d3}",
    "exec_endian": "flag{3nd14n_sw4p}",
    "exec_git": "flag{g1t_h1st0ry_l34ks}",
    "exec_pcap": "flag{http_p0st_b0dy}",
}

problems = []


# ── 1. 二进制 strings ────────────────────────────────────
def gen_strings():
    flag = FLAGS["exec_strings"]
    # 造一个"二进制"：ELF 魔法字节 + 随机二进制垃圾 + flag 明文 + 垃圾
    garbage = bytes(range(0, 256)) * 2
    data = b"\x7fELF\x02\x01\x01\x00" + garbage[:200] + flag.encode() + garbage[200:400]
    path = os.path.join(EXEC_DIR, "exec_strings.bin")
    with open(path, "wb") as f:
        f.write(data)
    problems.append({
        "id": "exec_strings", "category": "misc", "sub": "strings", "difficulty": "easy",
        "description": "用 strings 从二进制提取隐藏的 flag 字符串",
        "attachments": {"exec_strings.bin": "exec_strings.bin"},
        "flag_sha256": sha256(flag), "presolve_skill": "strings_flag",
    })


# ── 2. 网页源码 base64 ──────────────────────────────────
def gen_base64_source():
    flag = FLAGS["exec_base64_source"]
    b64 = base64.b64encode(flag.encode()).decode()
    html = (
        "<!DOCTYPE html><html><head><title>Login</title></head><body>\n"
        "  <!-- debug: flag base64 = %s -->\n"
        "  <form action='/login'><input name='u'><input name='p'></form>\n"
        "</body></html>\n" % b64
    )
    path = os.path.join(EXEC_DIR, "exec_source.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    problems.append({
        "id": "exec_base64_source", "category": "web", "sub": "source_audit", "difficulty": "easy",
        "description": "查看网页源码中的隐藏注释，base64 解码得到 flag",
        "attachments": {"exec_source.html": "exec_source.html"},
        "flag_sha256": sha256(flag), "presolve_skill": "web_source_audit",
    })


# ── 3. 免密 cookie ──────────────────────────────────────
def gen_cookie():
    flag = FLAGS["exec_cookie"]
    b64 = base64.b64encode(flag.encode()).decode()
    cookie = "session=%s; Path=/; HttpOnly" % b64
    path = os.path.join(EXEC_DIR, "exec_cookie.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(cookie + "\n")
    problems.append({
        "id": "exec_cookie", "category": "web", "sub": "cookie", "difficulty": "easy",
        "description": "浏览器 Cookie 中以 base64 存储了 flag，解码 Cookie 值得到 flag",
        "attachments": {"exec_cookie.txt": "exec_cookie.txt"},
        "flag_sha256": sha256(flag), "presolve_skill": "cookie_decode",
    })


# ── 4. 小端序 ───────────────────────────────────────────
def gen_endian():
    flag = FLAGS["exec_endian"]
    # 以小端序字节存放（真实题常把多字节值以小端写入文件）
    raw = flag.encode()
    le = raw[::-1]  # 等价于整体小端翻转（短字符串演示）
    path = os.path.join(EXEC_DIR, "exec_endian.bin")
    with open(path, "wb") as f:
        f.write(le)
    problems.append({
        "id": "exec_endian", "category": "misc", "sub": "encoding", "difficulty": "easy",
        "description": "文件以小端序存放了 flag 字节，翻转字节序解码得到 flag",
        "attachments": {"exec_endian.bin": "exec_endian.bin"},
        "flag_sha256": sha256(flag), "presolve_skill": "endian_swap",
    })


# ── 5. git 历史泄露 ─────────────────────────────────────
def gen_git():
    flag = FLAGS["exec_git"]
    repo = os.path.join(EXEC_DIR, "exec_git_repo")
    if os.path.exists(repo):
        import shutil
        shutil.rmtree(repo)
    os.makedirs(repo)
    env = dict(os.environ, GIT_AUTHOR_NAME="dev", GIT_AUTHOR_EMAIL="dev@x.io",
               GIT_COMMITTER_NAME="dev", GIT_COMMITTER_EMAIL="dev@x.io")
    subprocess.run(["git", "init", "-q", repo], check=True, env=env)
    subprocess.run(["git", "-C", repo, "config", "user.email", "dev@x.io"], check=True, env=env)
    subprocess.run(["git", "-C", repo, "config", "user.name", "dev"], check=True, env=env)
    # 第一次提交：含 flag 的 config
    with open(os.path.join(repo, "config.py"), "w", encoding="utf-8") as f:
        f.write("SECRET = '%s'\nAPI_KEY = 'abc123'\n" % flag)
    subprocess.run(["git", "-C", repo, "add", "-A"], check=True, env=env)
    subprocess.run(["git", "-C", repo, "commit", "-q", "-m", "init config"], check=True, env=env)
    # 第二次提交：移除 flag（历史仍保留）
    with open(os.path.join(repo, "config.py"), "w", encoding="utf-8") as f:
        f.write("API_KEY = 'abc123'\n")
    subprocess.run(["git", "-C", repo, "add", "-A"], check=True, env=env)
    subprocess.run(["git", "-C", repo, "commit", "-q", "-m", "remove secret"], check=True, env=env)
    problems.append({
        "id": "exec_git", "category": "misc", "sub": "git", "difficulty": "easy",
        "description": "git 仓库历史提交中曾泄露过密钥，git log -p 可找回 flag",
        "attachments": {"repo": "exec_git_repo"},
        "flag_sha256": sha256(flag), "presolve_skill": "git_history",
    })


# ── 6. HTTP pcap 取证 ───────────────────────────────────
def gen_pcap():
    flag = FLAGS["exec_pcap"]
    body = "username=admin&password=secret&flag=%s" % flag
    http = (
        "POST /login HTTP/1.1\r\n"
        "Host: target.ctf\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n%s" % (len(body), body)
    )
    payload = http.encode()
    # 构造最小 pcap：Ethernet(14) + IPv4(20) + TCP(20) + payload
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    ip = bytes.fromhex("45000261000040004006") + struct.pack(">H", 12345) + b"\xc0\xa8\x01\x10" + b"\xc0\xa8\x01\x01"
    tcp = struct.pack(">HHIIBBHHH", 54321, 80, 1000, 1, 5, 0x18, 0x7210, 0, 0) + b"\x00\x00"
    pkt = eth + ip + tcp + payload
    # pcap 全局头 (magic 0xa1b2c3d4 LE, v2.4, snaplen 65535, link 1)
    ghdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt
    path = os.path.join(EXEC_DIR, "exec_capture.pcap")
    with open(path, "wb") as f:
        f.write(ghdr + rec)
    problems.append({
        "id": "exec_pcap", "category": "misc", "sub": "forensics", "difficulty": "easy",
        "description": "tshark 提取 HTTP POST 请求体中的 flag",
        "attachments": {"exec_capture.pcap": "exec_capture.pcap"},
        "flag_sha256": sha256(flag), "presolve_skill": "pcap_http",
    })


if __name__ == "__main__":
    gen_strings()
    gen_base64_source()
    gen_cookie()
    gen_endian()
    gen_git()
    gen_pcap()
    bench = {"version": "execution-v1", "problems": {p["id"]: p for p in problems}}
    out = os.path.join(HERE, "execution_benchmark.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(bench, f, indent=2, ensure_ascii=False)
    print("生成 %d 个执行工件 -> %s" % (len(problems), out))
    for p in problems:
        print("  %s  sha=%s" % (p["id"], p["flag_sha256"][:12]))
