#!/usr/bin/env python3
"""
执行基准集工件生成器 v2：为 execution_benchmark.json v2 扩容题生成真实工件，
并幂等更新 benchmark JSON（新增 6 道文件型题：磁盘镜像 / 内存 dump / git 凭证
历史 / pcap GET 泄漏 / morse 工件 / 日志 b64 泄漏）。

运行（在仓库根目录）：
  python data/ctf_benchmark/gen_exec_artifacts_v2.py
"""
import base64
import hashlib
import json
import os
import shutil
import struct
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
EXEC_DIR = os.path.join(HERE, "execution")
BENCH = os.path.join(HERE, "execution_benchmark.json")

MORSE_TABLE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
}


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def encode_morse(text: str) -> str:
    return " ".join(MORSE_TABLE[c] for c in text.upper() if c in MORSE_TABLE)


# ── 工件生成 ──────────────────────────────────────────────

def gen_disk_image(path: str) -> None:
    """磁盘镜像：MBR + FAT 风格目录垃圾 + lost+found 中的 flag 文本块。"""
    flag = "picoCTF{d1sk_f0r3ns1cs_r0cks}"
    img = bytearray(8192)
    # MBR 引导扇区
    img[0:2] = b"\x33\xED"          # 典型 boot 跳转
    img[510:512] = b"\x55\xAA"
    img[3:11] = b"MSDOS5.0"
    # FAT 区域伪目录项
    fat = b"LOST+FOUN\x20\x20\x20\x10\x00" + b"\x00" * 11
    img[1024:1040] = fat
    img[2048:2112] = b"README .TXT\x20\x20" + b"\x00" * 12
    # 数据区：垃圾文件块 + flag 文本块（模拟已删除文件的残留簇）
    img[3072:3136] = b"This is a decoy text block for disk image padding......."
    off = 4096
    payload = b"deleted file cluster: " + flag.encode() + b" (recovered by carving)"
    img[off:off + len(payload)] = payload
    with open(path, "wb") as f:
        f.write(img)


def gen_memory_dump(path: str) -> None:
    """内存 dump：进程列表 + 堆碎片 + flag（模拟 volatility strings 扫描目标）。"""
    flag = "picoCTF{m3m0ry_dump_v0lat1l1ty}"
    procs = (
        b"[process list]\n"
        b"  0x804d1000  svchost.exe   pid=812\n"
        b"  0x8053b000  explorer.exe  pid=1044\n"
        b"  0x7ffd8000  notepad.exe   pid=2210\n"
    )
    heap = b"\xde\xad\xbe\xef" * 128
    chunk = b"user note: " + flag.encode() + b" <- volatile evidence"
    with open(path, "wb") as f:
        f.write(procs)
        f.write(heap)
        f.write(chunk)
        f.write(heap)


def gen_git_cred_repo(path: str) -> None:
    """git 仓库：第 2 个提交 credentials.txt 含 flag，第 3 个提交删除（历史泄露）。"""
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(path)
    env = dict(os.environ)
    env.update({"GIT_AUTHOR_NAME": "dev", "GIT_AUTHOR_EMAIL": "dev@example.com",
                "GIT_COMMITTER_NAME": "dev", "GIT_COMMITTER_EMAIL": "dev@example.com"})
    def git(*args):
        subprocess.run(["git", "-C", path] + list(args), check=True,
                       capture_output=True, env=env)
    git("init", "-q")
    git("config", "user.name", "dev")
    git("config", "user.email", "dev@example.com")
    with open(os.path.join(path, "app.py"), "w") as f:
        f.write("print('hello app v1')\n")
    git("add", "app.py")
    git("commit", "-qm", "init app")
    creds = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\napi_token = picoCTF{l34k3d_cr3d_in_g1t_h1st}\n"
    with open(os.path.join(path, "credentials.txt"), "w") as f:
        f.write(creds)
    git("add", "credentials.txt")
    git("commit", "-qm", "add deploy credentials")
    git("rm", "-q", "credentials.txt")
    git("commit", "-qm", "remove credentials (oops)")


def build_pcap(payloads: list) -> bytes:
    """最小 pcap：LE magic + Ethernet/IPv4/TCP 包序列（求解器只跳 54B 头扫载荷）。"""
    out = bytearray(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for i, payload in enumerate(payloads):
        eth = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x08\x00"
        ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + 20 + len(payload), i & 0xFFFF, 0x4000, 64, 6, 0)
        ip += b"\x0a\x00\x00\x01" + b"\x0a\x00\x00\x02"
        tcp = struct.pack(">HHIIBBHHH", 12345 + i, 80, i * 1000, 0, 0x50, 0x18, 8192, 0, 0)
        pkt = eth + ip + tcp + payload.encode("latin1")
        out += struct.pack("<IIII", i, 0, len(pkt), len(pkt)) + pkt
    return bytes(out)


def gen_pcap_get(path: str) -> None:
    """pcap：HTTP GET 请求 URL 携带 flag（等价 tshark 提取请求行）。"""
    payloads = [
        "GET /flag.php?token=flag{pcap_g3t_l34k_2026} HTTP/1.1\r\nHost: target.local\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    ]
    with open(path, "wb") as f:
        f.write(build_pcap(payloads))


def gen_morse_signal(path: str) -> None:
    """morse 工件：编码 flag 值（描述约定 flag{解码内容小写}），掺干扰行。"""
    core = "m0rs3c0d3f0r3ns1c5"
    with open(path, "w", encoding="utf-8") as f:
        f.write("intercepted signal transcript\n")
        f.write("noise line: .... .. / - .... . .-. .\n")
        f.write(encode_morse(core) + "\n")
        f.write("end of transcript\n")


def gen_access_log(path: str) -> None:
    """Web 访问日志：上千行噪音 + 一行 query param 为 b64(flag) 的泄漏请求。"""
    flag = "picoCTF{l0g_4ud1t_b64_l34k}"
    leak = base64.b64encode(flag.encode()).decode()
    lines = []
    for i in range(2000):
        lines.append('10.0.0.%d - - [08/Sep/2026:%02d:%02d:00 +0800] "GET /assets/app%d.js HTTP/1.1" 200 1024'
                     % (i % 250, i % 24, i % 60, i % 7))
    lines.insert(1337, '10.0.0.66 - - [08/Sep/2026:13:37:00 +0800] "GET /export?data=%s HTTP/1.1" 200 2048' % leak)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ── benchmark JSON 扩容（幂等） ─────────────────────────────

NEW_PROBLEMS = {
    "exec_disk_image": {
        "category": "misc", "sub": "forensics", "difficulty": "easy",
        "description": "磁盘镜像取证：从丢失分区恢复已删除文件中的 flag（等价 binwalk+strings 做簇 carving）",
        "attachments": {"disk_image.dd": "disk_image.dd"},
        "presolve_skill": "strings_flag",
        "note": "工件为 gen_exec_artifacts_v2.py 生成；等价真题 forensics_disk_image（真题镜像不可分发）",
    },
    "exec_memdump": {
        "category": "misc", "sub": "forensics", "difficulty": "easy",
        "description": "内存取证：对内存 dump 做 strings 扫描（等价 volatility strings 插件）找到 flag",
        "attachments": {"memory_dump.dmp": "memory_dump.dmp"},
        "presolve_skill": "strings_flag",
        "note": "工件为生成镜像；等价真题 forensics_mem_volatility（真题 dump 不可分发）",
    },
    "exec_git_cred": {
        "category": "misc", "sub": "git", "difficulty": "medium",
        "description": "git 历史审计：凭证文件被删除但仍在提交历史中，git log -p 找到泄露的 api_token flag",
        "attachments": {"repo": "git_cred_repo"},
        "presolve_skill": "git_history",
        "note": "等价真题 pico2024_gitcred；嵌套 .git 不入库，由本脚本再生成",
    },
    "exec_pcap_get": {
        "category": "misc", "sub": "forensics", "difficulty": "easy",
        "description": "流量分析：tshark 提取 HTTP GET 请求行中的 token flag（区别于既有 POST body 题）",
        "attachments": {"pcap_get.pcap": "pcap_get.pcap"},
        "presolve_skill": "pcap_http",
        "note": "工件为生成 pcap；等价真题 flag_in_pcap（GET 变体）",
    },
    "exec_morse": {
        "category": "misc", "sub": "morse", "difficulty": "medium",
        "description": "摩斯电码：解码信号文本（等价真题从图片提取后的产物），按 flag{解码内容小写} 提交",
        "attachments": {"morse_signal.txt": "morse_signal.txt"},
        "presolve_skill": "morse_decode",
        "note": "工件为 morse 文本（图片提取属视觉层，等价真题 public_morse_image）",
    },
    "exec_log_forensics": {
        "category": "misc", "sub": "forensics", "difficulty": "medium",
        "description": "日志审计：2000 行访问日志中定位一次异常 /export 请求，query param 为 base64 编码的 flag",
        "attachments": {"access_log.txt": "access_log.txt"},
        "presolve_skill": "web_source_audit",
        "note": "工件为生成日志；web_source_audit 求解器的 b64 扫描覆盖 query param 泄漏",
    },
}


def main() -> None:
    os.makedirs(EXEC_DIR, exist_ok=True)
    gen_disk_image(os.path.join(EXEC_DIR, "disk_image.dd"))
    gen_memory_dump(os.path.join(EXEC_DIR, "memory_dump.dmp"))
    gen_git_cred_repo(os.path.join(EXEC_DIR, "git_cred_repo"))
    gen_pcap_get(os.path.join(EXEC_DIR, "pcap_get.pcap"))
    gen_morse_signal(os.path.join(EXEC_DIR, "morse_signal.txt"))
    gen_access_log(os.path.join(EXEC_DIR, "access_log.txt"))
    print("artifacts generated in", EXEC_DIR)

    with open(BENCH, encoding="utf-8") as f:
        bench = json.load(f)
    added = 0
    for pid, p in NEW_PROBLEMS.items():
        if pid in bench["problems"]:
            continue
        flag = {
            "exec_disk_image": "picoCTF{d1sk_f0r3ns1cs_r0cks}",
            "exec_memdump": "picoCTF{m3m0ry_dump_v0lat1l1ty}",
            "exec_git_cred": "picoCTF{l34k3d_cr3d_in_g1t_h1st}",
            "exec_pcap_get": "flag{pcap_g3t_l34k_2026}",
            "exec_morse": "flag{m0rs3c0d3f0r3ns1c5}",
            "exec_log_forensics": "picoCTF{l0g_4ud1t_b64_l34k}",
        }[pid]
        p["flag_sha256"] = sha256(flag)
        bench["problems"][pid] = p
        added += 1
    bench["version"] = "v2-exec"
    with open(BENCH, "w", encoding="utf-8") as f:
        json.dump(bench, f, ensure_ascii=False, indent=2)
    print("benchmark updated: +%d problems (total %d)" % (added, len(bench["problems"])))


if __name__ == "__main__":
    main()
