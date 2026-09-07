# -*- coding: utf-8 -*-
"""附件取证基准 —— Python 侧独立复刻（与 Go forensics_binary.go 互为校验）。

纪律：
  1. 完全独立实现（只用标准库：struct/zlib/zipfile/base64/binascii/urllib），
     不调用 Go、不读 Go 结果，两边各自解析同一份真实产物。
  2. 判定走 SHA-256，只认哈希。
  3. 反注水：朴素正则在原始字节上必须扫不到，否则判该题为「注水」并报错。

用法：python judge_attachment.py
"""
import base64
import binascii
import hashlib
import json
import os
import re
import struct
import sys
import urllib.parse
import zipfile
import zlib

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 与 Go flagRegexPresolve / flagRegexUppercase / flagShapeRegex 同构
FLAG_RE = re.compile(
    r'(?i)[a-zA-Z0-9_]*(?:flag|ctf|dasctf|key|grodno|nicc|ehax|bzhctf)'
    r'[a-zA-Z0-9_]*\s*[=:：]?\s*\{([^}]{4,})\}'.encode())
FLAG_RE_UPPER = re.compile(rb'\b[A-Z][A-Z0-9]{2,15}\{([^}]{4,})\}')
FLAG_SHAPE_RE = re.compile(rb'[A-Za-z0-9_]{2,20}\{[^}\s]{4,}\}')

B64_RE = re.compile(rb'[A-Za-z0-9+/=_-]{16,}')
HEX_RE = re.compile(rb'(?:0x)?[0-9a-fA-F]{16,}')


def sha(s):
    return hashlib.sha256(s if isinstance(s, bytes) else s.encode()).hexdigest()


def printable_flag(m):
    """真 flag 必须是干净可打印 ASCII（与 Go isPrintableFlagCandidate 同口径）。"""
    if not m or len(m) > 128:
        return False
    return all(0x20 <= b < 0x7f for b in m)


def scan_raw(data):
    out = []
    for rx in (FLAG_RE, FLAG_RE_UPPER, FLAG_SHAPE_RE):
        for m in rx.findall(data) if rx is FLAG_SHAPE_RE else []:
            pass
    for rx in (FLAG_RE, FLAG_RE_UPPER):
        for m in rx.finditer(data):
            s = m.group(0)
            if printable_flag(s):
                out.append(s)
    # 通用外形兜底（需可打印）
    for m in FLAG_SHAPE_RE.finditer(data):
        s = m.group(0)
        if printable_flag(s):
            out.append(s)
    seen, res = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            res.append(s)
    return res


def utf16_variants(data):
    """strings -e l / -e b：抽取 ASCII+NUL 交错区。"""
    out = []
    if len(data) < 8:
        return out
    for big in (False, True):
        buf, start = bytearray(), -1
        n = len(data) - 1
        i = 0
        while i < n:
            ascii_byte = 0
            if big:
                if data[i] == 0:
                    ascii_byte = data[i + 1]
            else:
                if data[i + 1] == 0:
                    ascii_byte = data[i]
            ok = 0x20 <= ascii_byte < 0x7f
            if ok and start < 0:
                start = i
            elif not ok and start >= 0:
                if i - start >= 12:
                    seg = data[start:i]
                    buf += bytes(seg[1::2] if big else seg[0::2])
                start = -1
            i += 2
        if start >= 0 and n - start >= 12:
            seg = data[start:n]
            buf += bytes(seg[1::2] if big else seg[0::2])
        if buf:
            out.append(bytes(buf))
    return out


def b64_decoded(data):
    out = []
    for m in B64_RE.findall(data)[:64]:
        s = m.rstrip(b'=')
        if len(s) < 16:
            continue
        try:
            if len(s) % 4 == 0:
                out.append(base64.b64decode(s, validate=False))
            else:
                out.append(base64.urlsafe_b64decode(s + b'=' * (-len(s) % 4)))
        except Exception:
            continue
    return out


def hex_decoded(data):
    out = []
    for m in HEX_RE.findall(data)[:32]:
        s = m[2:] if m[:2] in (b'0x', b'0X') else m
        if len(s) % 2:
            s = s[:-1]
        try:
            out.append(binascii.unhexlify(s))
        except Exception:
            continue
    return out


def scan_variants(data):
    out = list(scan_raw(data))
    for v in utf16_variants(data):
        out += scan_raw(v)
    for d in b64_decoded(data):
        out += scan_raw(d)
    for d in hex_decoded(data):
        out += scan_raw(d)
    if b'%' in data:
        try:
            dec = urllib.parse.unquote(data.decode('latin-1')).encode('latin-1')
            if dec != data:
                out += scan_raw(dec)
        except Exception:
            pass
    if len(data) <= (1 << 20):
        out += scan_raw(data[::-1])
    seen, res = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            res.append(s)
    return res


# ───────────────────────── PNG ─────────────────────────

def png_chunks(data):
    pos, chunks = 8, []
    while pos + 12 <= len(data):
        ln = struct.unpack('>I', data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + ln]
        chunks.append((typ, body))
        pos += 12 + ln
        if typ == b'IEND':
            break
    return chunks, pos


def png_pixels(data):
    """纯标准库 PNG 解码（8bit RGB/RGBA/灰度），返回 (w, h, bpp, pixels)。"""
    chunks, _ = png_chunks(data)
    idat, w, h, bd, ct = b'', 0, 0, 8, 2
    for typ, body in chunks:
        if typ == b'IHDR':
            w, h, bd, ct = struct.unpack('>IIBB', body[:10])
        elif typ == b'IDAT':
            idat += body
    raw = zlib.decompress(idat)
    ch = {0: 1, 2: 3, 4: 2, 6: 4}[ct]
    bpp = ch * (bd // 8)
    stride = w * bpp
    out, prev, i = bytearray(), bytearray(stride), 0
    for _ in range(h):
        f = raw[i]
        i += 1
        line = bytearray(raw[i:i + stride])
        i += stride
        if f == 1:
            for x in range(bpp, stride):
                line[x] = (line[x] + line[x - bpp]) & 0xFF
        elif f == 2:
            for x in range(stride):
                line[x] = (line[x] + prev[x]) & 0xFF
        elif f == 3:
            for x in range(stride):
                a = line[x - bpp] if x >= bpp else 0
                line[x] = (line[x] + ((a + prev[x]) >> 1)) & 0xFF
        elif f == 4:
            for x in range(stride):
                a = line[x - bpp] if x >= bpp else 0
                b = prev[x]
                c = prev[x - bpp] if x >= bpp else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[x] = (line[x] + pr) & 0xFF
        out += line
        prev = line
    return w, h, bpp, bytes(out)


def lsb_extract(pixels, bpp, channels=(0, 1, 2), msb=True, max_bytes=8192):
    bits = []
    for i in range(0, len(pixels), bpp):
        for c in channels:
            if c >= bpp:
                continue
            bits.append(pixels[i + c] & 1)
            if len(bits) >= max_bytes * 8:
                break
        if len(bits) >= max_bytes * 8:
            break
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for k in range(8):
            if msb:
                byte |= bits[i + k] << (7 - k)
            else:
                byte |= bits[i + k] << k
        out.append(byte)
    return bytes(out)


def solve_png_lsb(data):
    w, h, bpp, px = png_pixels(data)
    out = []
    for channels in ((0, 1, 2), (0,), (0, 1, 2, 3)):
        for msb in (True, False):
            out += scan_variants(lsb_extract(px, bpp, channels, msb))
    return out


def solve_png_meta(data):
    chunks, end = png_chunks(data)
    out, texts = [], b''
    for typ, body in chunks:
        if typ in (b'tEXt', b'iTXt'):
            texts += body + b'\n'
        elif typ == b'zTXt':
            z = body.find(b'\x00')
            if z >= 0 and z + 2 <= len(body):
                try:
                    texts += zlib.decompress(body[z + 2:]) + b'\n'
                except Exception:
                    pass
    if texts:
        out += scan_variants(texts)
    if end < len(data):
        out += scan_variants(data[end:])
    return out


def solve_jpeg_meta(data):
    if not data.startswith(b'\xff\xd8'):
        return []
    out, texts, i = [], bytearray(), 2
    while i + 4 <= len(data):
        if data[i] != 0xFF:
            break
        marker = data[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if marker == 0xD9:
            if i + 2 < len(data):
                out += scan_variants(data[i + 2:])
            break
        seglen = struct.unpack('>H', data[i + 2:i + 4])[0]
        if seglen < 2 or i + 2 + seglen > len(data):
            break
        if marker == 0xFE or 0xE0 <= marker <= 0xEF:
            texts += data[i + 4:i + 2 + seglen] + b'\n'
        i += 2 + seglen
    if texts:
        out += scan_variants(bytes(texts))
    return out


# ───────────────────────── pcap ─────────────────────────

def tcp_payload(pkt, link):
    if link == 1:
        if len(pkt) < 14:
            return None
        et = struct.unpack('>H', pkt[12:14])[0]
        if et == 0x8100:
            if len(pkt) < 18 or struct.unpack('>H', pkt[16:18])[0] != 0x0800:
                return None
            ip_off = 18
        elif et == 0x0800:
            ip_off = 14
        else:
            return None
    elif link in (101, 228, 12, 14):
        ip_off = 0
    elif link == 113:
        ip_off = 16
    elif link == 0:
        ip_off = 4
    else:
        ip_off = 14
    if ip_off + 20 > len(pkt):
        return None
    ip = pkt[ip_off:]
    if ip[0] >> 4 != 4 or ip[9] != 6:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack('>H', ip[2:4])[0]
    tcp = ip[ihl:total] if total >= 20 and total - ihl <= len(ip) else ip[ihl:]
    if len(tcp) < 20:
        return None
    doff = (tcp[12] >> 4) * 4
    if doff < 20 or doff > len(tcp):
        return None
    return tcp[doff:]


def solve_pcap(data):
    out = []
    if len(data) >= 24:
        le = struct.unpack('<I', data[:4])[0] == 0xa1b2c3d4
        be = struct.unpack('>I', data[:4])[0] == 0xa1b2c3d4
        if le or be:
            fmt = '<' if le else '>'
            link = struct.unpack(fmt + 'I', data[20:24])[0]
            pos = 24
            while pos + 16 <= len(data):
                incl = struct.unpack(fmt + 'I', data[pos + 8:pos + 12])[0]
                pos += 16
                if incl <= 0 or pos + incl > len(data):
                    break
                pl = tcp_payload(data[pos:pos + incl], link)
                pos += incl
                if pl:
                    out += scan_variants(pl)
    if len(data) >= 12 and struct.unpack('>I', data[:4])[0] == 0x0a0d0d0a:
        pos, links, iface = 0, {}, 0
        while pos + 12 <= len(data):
            btype = struct.unpack('<I', data[pos:pos + 4])[0]
            blen = struct.unpack('<I', data[pos + 4:pos + 8])[0]
            if blen < 12 or pos + blen > len(data):
                break
            if btype == 1 and blen >= 12:
                links[iface] = struct.unpack('<H', data[pos + 8:pos + 10])[0]
                iface += 1
            elif btype == 6 and blen >= 32:
                ifid = struct.unpack('<I', data[pos + 8:pos + 12])[0]
                caplen = struct.unpack('<I', data[pos + 20:pos + 24])[0]
                start = pos + 28
                if 0 < caplen and start + caplen <= pos + blen:
                    pl = tcp_payload(data[start:start + caplen], links.get(ifid, 1))
                    if pl:
                        out += scan_variants(pl)
            pos += blen
    seen, res = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            res.append(s)
    return res


# ───────────────────────── ZIP / 雕刻 / XOR ─────────────────────────

def solve_zip(data, depth=0):
    import io
    out = []
    if depth > 2:
        return out
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return out
    for name in zf.namelist():
        try:
            content = zf.read(name)
        except Exception:
            continue
        out += scan_variants(content)
        out += scan_raw(name.encode())
        if name.lower().endswith(('.zip', '.apk', '.docx')):
            out += solve_zip(content, depth + 1)
    return out


MAGICS = [(b'PK\x03\x04', 'zip'), (b'\x89PNG\r\n\x1a\n', 'png'), (b'\xff\xd8\xff', 'jpeg'),
          (b'GIF87a', 'raw'), (b'GIF89a', 'raw'), (b'%PDF-', 'raw'),
          (b'\x1f\x8b\x08', 'raw'), (b'Rar!\x1a\x07', 'raw'), (b'7z\xbc\xaf\x27\x1c', 'raw')]


def solve_carve(data):
    out = []
    for sig, kind in MAGICS:
        start, found = 1, 0
        while found < 4:
            idx = data.find(sig, start)
            if idx < 0:
                break
            start = idx + len(sig)
            found += 1
            rest = data[idx:idx + (8 << 20)]
            if kind == 'zip':
                out += solve_zip(rest, 1)
            elif kind == 'png':
                out += solve_png_meta(rest)
                out += scan_variants(rest[:1 << 20])
            elif kind == 'jpeg':
                out += solve_jpeg_meta(rest)
            else:
                out += scan_variants(rest[:1 << 20])
    return out


def mostly_printable(b):
    if not b:
        return False
    n = min(len(b), 512)
    ok = sum(1 for i in range(n) if b[i] in (9, 10, 13) or 0x20 <= b[i] < 0x7f)
    return ok * 10 >= n * 9


def solve_xor_crib(data):
    data = data[:1 << 18]
    cribs = [b'flag{', b'picoCTF{', b'ctf{', b'CTF{', b'FLAG{']
    out = []
    for period in range(1, 9):
        for crib in cribs:
            if period > len(crib):
                continue
            for off in range(0, min(256, len(data))):
                if off + len(crib) > len(data):
                    break
                key = bytes(data[off + i] ^ crib[i % len(crib)] for i in range(period))
                if any(data[off + i] ^ key[i % period] != crib[i] for i in range(period, len(crib))):
                    continue
                n = min(len(data) - off, 4096)
                plain = bytes(data[off + i] ^ key[i % period] for i in range(n))
                if mostly_printable(plain):
                    out += scan_variants(plain)
    return out


SOLVERS = {
    'bin_strings': scan_variants,
    'bin_png_lsb': solve_png_lsb,
    'bin_png_meta': solve_png_meta,
    'bin_jpeg_meta': solve_jpeg_meta,
    'bin_pcap_http': solve_pcap,
    'bin_zip_inner': solve_zip,
    'bin_carve': solve_carve,
    'bin_xor_crib': solve_xor_crib,
}


def main():
    bench = os.path.join(BASE, 'data', 'ctf_benchmark', 'attachment_benchmark.json')
    doc = json.load(open(bench, encoding='utf-8'))
    problems = doc['problems']
    hit = 0
    water = 0
    for pid in sorted(problems):
        p = problems[pid]
        path = os.path.join(BASE, 'data', 'ctf_benchmark', p['attachment'])
        data = open(path, 'rb').read()
        # 反注水：朴素正则在原始字节上不许命中
        if any(sha(f) == p['flag_sha256'] for f in scan_raw(data)):
            print(f"💧 {pid}: 朴素正则即可命中 —— 题目注水")
            water += 1
        fn = SOLVERS[p['presolve_skill']]
        flags = fn(data)
        if any(sha(f) == p['flag_sha256'] for f in flags):
            hit += 1
            print(f"✅ {pid:<26} {p['presolve_skill']}")
        else:
            print(f"❌ {pid:<26} {p['presolve_skill']} 未命中")
    print(f"=== Python 侧附件取证基准: {hit}/{len(problems)} = "
          f"{hit * 100.0 / max(1, len(problems)):.1f}% （注水题 {water}）===")
    return 0 if hit == len(problems) and water == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
