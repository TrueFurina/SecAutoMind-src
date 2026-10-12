# -*- coding: utf-8 -*-
"""生成「真实二进制取证」基准产物（data/ctf_benchmark/artifacts/）。

纪律：产物必须是**真格式**——真 PNG（IHDR/IDAT/IEND + CRC32 + zlib）、
真 pcap（链路层/IPv4/TCP/HTTP 报文）、真 ZIP（deflate 压缩流）、真 XOR 密文，
不是把 flag 硬塞进文本文件冒充。且每个产物的 flag 都做了编码/隐藏处理，
朴素 flag 正则（scanFlags）在原始字节上**扫不到**，必须靠真实解析才能出。

同时生成 attachment_benchmark.json（只落 flag 的 SHA-256，不明文落答案）。
"""
import hashlib
import json
import os
import random
import socket
import struct
import urllib.parse
import zlib
import zipfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART = os.path.join(BASE, 'data', 'ctf_benchmark', 'artifacts')
os.makedirs(ART, exist_ok=True)

random.seed(20260908)


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# ───────────────────────── PNG 构造（无第三方依赖） ─────────────────────────

def png_chunk(typ: bytes, data: bytes) -> bytes:
    return struct.pack('>I', len(data)) + typ + data + struct.pack('>I', zlib.crc32(typ + data) & 0xffffffff)


def make_png(width, height, pixels: bytearray) -> bytes:
    """pixels: RGB 原始像素（长度 width*height*3）。"""
    raw = b''
    for y in range(height):
        raw += b'\x00' + bytes(pixels[y * width * 3:(y + 1) * width * 3])
    ihdr = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)  # 8bit RGB
    return (b'\x89PNG\r\n\x1a\n'
            + png_chunk(b'IHDR', ihdr)
            + png_chunk(b'IDAT', zlib.compress(raw, 9))
            + png_chunk(b'IEND', b''))


def rand_pixels(w, h):
    return bytearray(random.randrange(256) for _ in range(w * h * 3))


def embed_lsb(pixels: bytearray, payload: bytes) -> None:
    """把 payload 按 MSB-first 写进 R/G/B 通道最低位（与 Go bfxPNGLsb 位序一致）。"""
    bits = ''.join(f'{b:08b}' for b in payload)
    for i, bit in enumerate(bits):
        if i >= len(pixels):
            break
        pixels[i] = (pixels[i] & 0xFE) | int(bit)


# ───────────────────────── pcap 构造 ─────────────────────────

def ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def build_tcp_packet(payload: bytes, sport=54321, dport=80) -> bytes:
    src, dst = '10.0.0.7', '10.0.0.1'
    tcp = struct.pack('>HHIIBBHHH', sport, dport, 1, 1, (5 << 4), 0x18, 8192, 0, 0)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack('>BBHHHBBH', 0x45, 0, total, 0x1234, 0, 64, 6, 0) \
        + socket.inet_aton(src) + socket.inet_aton(dst)
    ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
    eth = b'\xaa\xbb\xcc\xdd\xee\xff' + b'\x11\x22\x33\x44\x55\x66' + b'\x08\x00'
    return eth + ip + tcp + payload


def make_pcap(packets):
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)  # linktype=1 Ethernet
    for i, pkt in enumerate(packets):
        out += struct.pack('<IIII', 1700000000 + i, 0, len(pkt), len(pkt)) + pkt
    return out


# ───────────────────────── 产物定义 ─────────────────────────

problems = {}


def add(pid, category, description, filename, flag, presolve_skill):
    problems[pid] = {
        'id': pid,
        'category': category,
        'description': description,
        'attachment': 'artifacts/' + filename,
        'flag_sha256': sha(flag),
        'presolve_skill': presolve_skill,
    }


# 1) PNG LSB 隐写（flag 只存在于像素最低位）
FLAG_LSB = 'flag{lsb_p1x3l_st3g0_2026}'
px = rand_pixels(64, 64)
embed_lsb(px, FLAG_LSB.encode() + b'\x00')
open(os.path.join(ART, 'stego_lsb.png'), 'wb').write(make_png(64, 64, px))
add('artifact_png_lsb', 'misc',
    '下载这张 PNG，flag 藏在像素里。提示：LSB 最低有效位隐写。',
    'stego_lsb.png', FLAG_LSB, 'bin_png_lsb')

# 2) PNG tEXt 元数据（base64 编码，原始字节扫不到）
FLAG_TEXT = 'picoCTF{t3xt_chunk_m3tadata}'
import base64 as _b64
px2 = rand_pixels(48, 48)
png2 = make_png(48, 48, px2)
png2 = png2[:-12] + png_chunk(b'tEXt', b'Comment\x00' + _b64.b64encode(FLAG_TEXT.encode())) + png2[-12:]
open(os.path.join(ART, 'meta_text.png'), 'wb').write(png2)
add('artifact_png_text', 'misc',
    '这张图片看起来很普通，检查一下元数据。提示：exiftool / PNG 文本块。',
    'meta_text.png', FLAG_TEXT, 'bin_png_meta')

# 3) PNG IEND 之后附加数据（base64）
FLAG_TAIL = 'flag{t41l_d4ta_aft3r_1end}'
px3 = rand_pixels(32, 32)
png3 = make_png(32, 32, px3) + _b64.b64encode(FLAG_TAIL.encode())
open(os.path.join(ART, 'tail_data.png'), 'wb').write(png3)
add('artifact_png_tail', 'misc',
    '文件尾部好像多出了一截。提示：binwalk / 检查 IEND 之后的数据。',
    'tail_data.png', FLAG_TAIL, 'bin_png_meta')

# 4) JPEG COM 注释段
FLAG_JPEG = 'flag{jp3g_c0mm3nt_s3gm3nt}'
jpg = b'\xff\xd8' + struct.pack('>HH', 0xFFFE, 2 + 2 + len(_b64.b64encode(FLAG_JPEG.encode())))
jpg = b'\xff\xd8' + b'\xff\xfe' + struct.pack('>H', 2 + len(_b64.b64encode(FLAG_JPEG.encode()))) \
    + _b64.b64encode(FLAG_JPEG.encode()) + b'\xff\xd9' + bytes(random.randrange(256) for _ in range(64))
open(os.path.join(ART, 'comment.jpg'), 'wb').write(jpg)
add('artifact_jpeg_com', 'misc',
    '一张 JPEG，注释里可能有东西。提示：strings / COM 段。',
    'comment.jpg', FLAG_JPEG, 'bin_jpeg_meta')

# 5) pcap：HTTP POST，flag 百分号编码在 body 里（需解析 TCP 载荷 + URL 解码）
FLAG_PCAP = 'flag{pcap_http_p0st_2026}'
body = 'user=admin&note=' + urllib.parse.quote(FLAG_PCAP, safe='')
req = ('POST /submit HTTP/1.1\r\nHost: range.local\r\n'
       'Content-Type: application/x-www-form-urlencoded\r\n'
       f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n' + body).encode()
noise = ('GET /static/app.js HTTP/1.1\r\nHost: range.local\r\n\r\n').encode()
open(os.path.join(ART, 'traffic.pcap'), 'wb').write(
    make_pcap([build_tcp_packet(noise, 54320, 80), build_tcp_packet(req, 54321, 80)]))
add('artifact_pcap_http', 'misc',
    '抓到了一段流量，flag 应该在 HTTP 请求里。提示：tshark / 导出 HTTP 对象。',
    'traffic.pcap', FLAG_PCAP, 'bin_pcap_http')

# 6) ZIP 内层文件（deflate 压缩，原始字节扫不到）
FLAG_ZIP = 'flag{z1p_1nn3r_f1l3_h3r3}'
with zipfile.ZipFile(os.path.join(ART, 'bundle.zip'), 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('readme.txt', 'nothing here\n')
    z.writestr('inner/deep/flag.txt', f'congrats: {FLAG_ZIP}\n')
add('artifact_zip_inner', 'misc',
    '一个压缩包，解压看看里面。提示：zip / 注意子目录。',
    'bundle.zip', FLAG_ZIP, 'bin_zip_inner')

# 7) 文件雕刻：垃圾数据 + 嵌入 ZIP（偏移 > 0）
FLAG_CARVE = 'flag{c4rv3d_3mb3dd3d_z1p}'
buf = bytearray(bytes(random.randrange(256) for _ in range(4096)))
import io as _io
zbuf = _io.BytesIO()
with zipfile.ZipFile(zbuf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('secret.txt', FLAG_CARVE)
open(os.path.join(ART, 'carve_blob.bin'), 'wb').write(bytes(buf) + zbuf.getvalue())
add('artifact_carve_zip', 'misc',
    '这个文件里好像还藏着别的文件。提示：binwalk / foremost 提取。',
    'carve_blob.bin', FLAG_CARVE, 'bin_carve')

# 8) 重复密钥 XOR（已知明文恢复）
FLAG_XOR = 'flag{x0r_r3p34t1ng_k3y_rc4}'
key = b'k3y'
plain = (FLAG_XOR + ' padding text to make it realistic ').encode()
ct = bytes(plain[i] ^ key[i % len(key)] for i in range(len(plain)))
open(os.path.join(ART, 'xor_blob.bin'), 'wb').write(bytes(random.randrange(256) for _ in range(64)) + ct)
add('artifact_xor_crib', 'crypto',
    '这段数据被 XOR 加密了，密钥应该是短的。flag 格式已知。',
    'xor_blob.bin', FLAG_XOR, 'bin_xor_crib')

# 9) 二进制里的 base64 串
FLAG_B64 = 'flag{b64_h1dd3n_1n_b1nary}'
blob = bytearray(bytes(random.randrange(256) for _ in range(2048)))
tok = _b64.b64encode(FLAG_B64.encode())
blob[1024:1024 + len(tok)] = tok
open(os.path.join(ART, 'b64_blob.bin'), 'wb').write(bytes(blob))
add('artifact_b64_binary', 'misc',
    '固件里有一段可疑的长字符串。提示：strings 之后 base64 -d。',
    'b64_blob.bin', FLAG_B64, 'bin_strings')

# 10) UTF-16LE 宽字符串
FLAG_UTF16 = 'flag{utf16_w1d3_str1ng_h3r3}'
u16 = FLAG_UTF16.encode('utf-16-le')
open(os.path.join(ART, 'utf16_blob.bin'), 'wb').write(
    bytes(random.randrange(256) for _ in range(128)) + u16 + bytes(random.randrange(256) for _ in range(64)))
add('artifact_utf16_binary', 'misc',
    '内存 dump 里的字符串是宽字符。提示：UTF-16。',
    'utf16_blob.bin', FLAG_UTF16, 'bin_strings')

doc = {
    'version': 'attachment-forensics-1.0',
    'note': '真实二进制取证基准：flag 均经编码/隐藏处理，朴素文本正则在原始字节上扫不到，'
            '必须做真实解析（PNG 解码/块解析、pcap 报文解析、ZIP 解压、XOR 已知明文恢复等）。'
            '只存 flag 的 SHA-256，不明文落答案。',
    'problems': problems,
}
with open(os.path.join(BASE, 'data', 'ctf_benchmark', 'attachment_benchmark.json'), 'w', encoding='utf-8') as f:
    json.dump(doc, f, ensure_ascii=False, indent=2)

print('产物目录:', ART)
for k, v in problems.items():
    p = os.path.join(BASE, 'data', 'ctf_benchmark', v['attachment'])
    print(f"  {v['attachment']:<24} {os.path.getsize(p):>8} B  {k}")
print('题目数:', len(problems))
