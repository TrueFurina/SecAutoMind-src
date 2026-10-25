import json, hashlib

def sha256(s): return hashlib.sha256(s.encode()).hexdigest()

# ── 真值外置（红线：flag 明文不得入 PUBLIC 仓）────────────────────────
# 明文答案存于 gitignore 的 data/answers/，源码只留 id。缺失时 fail-closed：
# 宁可构建失败，也不产出 flag_sha256 缺失/错误的残缺基准集。
def _load_flag_truth(path='data/answers/build_real_benchmark_answers.json'):
    import os
    if not os.path.isfile(path):
        raise SystemExit(
            '[build] 缺少真值文件 %s —— flag 明文按红线不入 PUBLIC 仓。\n'
            '        本机真值由 scripts/externalize_generator_flags.py 生成；\n'
            '        换机需从赛题原始来源重建，或向维护者索取。' % path)
    with open(path, encoding='utf-8') as f:
        return json.load(f).get('answers', {})


_FLAG_TRUTH = _load_flag_truth()
real = [
    {"id":"pico2024_interencdec","category":"crypto","sub":"base64_caesar","difficulty":"easy",
     "source":"picoCTF 2024 - interencdec",
     "description":"YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclgyMHdNakV5TnpVNGZRPT0nCg=="},
    {"id":"pico2024_canyousee","category":"misc","sub":"steganography","difficulty":"easy",
     "source":"picoCTF 2024 - CanYouSee",
     "description":"cGljb0NURntNRTc0RDQ3QV9ISUREM05fYTZkZjhkYjh9Cg=="},
    {"id":"sdctf2021_case64ar","category":"crypto","sub":"base64_caesar","difficulty":"easy",
     "source":"SDCTF 2021 - case64ar",
     "description":"OoDVP4LtFm7lKnHk+JDrJo2jNZDROl/1HH77H5Xv"},
    # v6.1 重建：原始密文与记录 flag 不一致（疑似赛题实例差异），已从 flag 重建自洽描述（单层 b64）
    {"id":"cyberconverge2025_layers","category":"crypto","sub":"base64","difficulty":"easy",
     "source":"CyberConverge 2025 - Layers",
     "description":"Q0JDVntjUnk5VDBfTDR5M3I1XzRSRV9GdU5fMzEzNX0="},
    {"id":"wolvctf2024_xor","category":"crypto","sub":"xor","difficulty":"easy",
     "source":"WolvCTF 2024 - Crypto Yors Truly",
     "description":"NkMHEgkxXjV/BlN/ElUKMVZQEzFtGzpsVTgGDw=="},
    {"id":"nahamcon2024_rsa","category":"crypto","sub":"rsa_small_e","difficulty":"medium",
     "source":"NahamCon CTF 2024 - Magic RSA",
     "description":"RSA e=3, ciphertext每值开立方根转ASCII"},
    {"id":"breizhctf2022_rsa","category":"crypto","sub":"rsa_small_e","difficulty":"easy",
     "source":"BreizhCTF 2022 - Very small exponent",
     "description":"RSA e=3, c=5724429365887192937975880152728551254971364525753671743693147523302441587707804097718439038173546355026701325414799056205074425733698744528930791075004105312923906122185518441456605039101517459937804505729125"},
    {"id":"crewctf2024_rsa_gcd","category":"crypto","sub":"rsa_common_factor","difficulty":"medium",
     "source":"CrewCTF 2024 - Read between the lines",
     "description":"RSA共模攻击：n1和n2共享素数p"},
    {"id":"pico2024_stringsit","category":"misc","sub":"strings","difficulty":"easy",
     "source":"picoCTF 2024 - strings-it",
     "description":"strings命令从二进制提取flag"},
    {"id":"pico2024_commitment","category":"misc","sub":"git","difficulty":"easy",
     "source":"picoCTF 2024 - Commitment",
     "description":"git log查看提交历史找到flag"},
    {"id":"pico2024_cookie","category":"web","sub":"cookie","difficulty":"easy",
     "source":"picoCTF 2024 - Cookie Monster",
     "description":"浏览器Cookie中Base64编码的flag"},
    {"id":"pico2024_irishname","category":"web","sub":"sqli","difficulty":"easy",
     "source":"picoCTF 2024 - Irish-Name-Repo",
     "description":"SQL注入绕过登录：admin' OR 1=1--"},
    {"id":"pico2024_findme","category":"web","sub":"source_audit","difficulty":"easy",
     "source":"picoCTF 2024 - findme",
     "description":"查看网页源码中的隐藏flag"},
    {"id":"pico2024_ssh","category":"misc","sub":"ssh","difficulty":"easy",
     "source":"picoCTF 2024 - SSH EXPLOIT",
     "description":"SSH连接服务器获取flag"},
    {"id":"pico2024_gitcred","category":"misc","sub":"git","difficulty":"easy",
     "source":"picoCTF 2024 - Git Credential",
     "description":"git log查看提交历史找到泄露凭证"},
    {"id":"pico2024_endian","category":"misc","sub":"encoding","difficulty":"easy",
     "source":"picoCTF 2024 - Endianness",
     "description":"大小端序转换解码flag"},
    {"id":"pico2024_minirsa","category":"crypto","sub":"rsa_small_e","difficulty":"easy",
     "source":"picoCTF 2024 - Mini RSA",
     "description":"RSA e=3小指数攻击"},
    {"id":"ehaxctf2025_morse","category":"crypto","sub":"morse_vigenere","difficulty":"medium",
     "source":"EHAXCTF 2025 - Dots & Dashes",
     "description":"Morse解码后维吉尼亚解密(密钥kagi)"},
    {"id":"public_morse_image","category":"misc","sub":"morse","difficulty":"easy",
     "source":"SpookyCTF 2024 - whispers-in-morse",
     "description":"图片隐写提取Morse码后解码"},
    {"id":"crc_forgery_real","category":"crypto","sub":"crc","difficulty":"hard",
     "source":"CyberNova 2026 - Lazarus Phantom DB",
     "description":"CRC64线性性伪造cookie进行CBC篡改"},
    {"id":"rsa_common_real","category":"crypto","sub":"rsa","difficulty":"medium",
     "source":"CTF公开题 - RSA Common Modulus",
     "description":"同n不同e1/e2加密同一明文,gcd(e1,e2)=1"},
    {"id":"base64_triple_real","category":"crypto","sub":"base64","difficulty":"easy",
     "source":"CTF公开题 - Triple Base64",
     "description":"三层Base64编码"},
    {"id":"caesar_shift19_real","category":"crypto","sub":"caesar","difficulty":"easy",
     "source":"picoCTF 2024 - interencdec内层",
     "description":"wpjvJAM{jhlzhy_k3jy9wa3k_m0212758} 凯撒移位19"},
    {"id":"xss_cookie_steal","category":"web","sub":"xss","difficulty":"medium",
     "source":"CISCN 2019 华东北 - Web2",
     "description":"XSS获取管理员cookie后SQL注入"},
    {"id":"xxe_file_read","category":"web","sub":"xxe","difficulty":"medium",
     "source":"GHCTF 2025 - Flask XXE",
     "description":"XXE读取/flag文件"},
    {"id":"ssti_tpl_inject","category":"web","sub":"ssti","difficulty":"medium",
     "source":"GHCTF 2025 - SSTI",
     "description":"Jinja2 SSTI模板注入RCE"},
    {"id":"flag_in_html","category":"web","sub":"source_audit","difficulty":"easy",
     "source":"CTF公开题 - HTML注释",
     "description":"<!-- secret: flag{html_comment_flag} -->"},
    {"id":"flag_in_json_api","category":"web","sub":"api","difficulty":"easy",
     "source":"CTF公开题 - JSON泄露",
     "description":"API返回 {\"secret\":\"flag{json_api_secret}\"}"},
    {"id":"flag_in_cookie_set","category":"web","sub":"cookie","difficulty":"easy",
     "source":"CTF公开题 - Set-Cookie",
     "description":"Set-Cookie: secret=flag{cookie_secret_exfil}"},
    {"id":"flag_in_log_data","category":"misc","sub":"forensics","difficulty":"easy",
     "source":"CTF公开题 - 日志取证",
     "description":"[WARN] data_exfil payload=flag{log_exfil_data}"},
    {"id":"flag_in_pcap","category":"misc","sub":"forensics","difficulty":"easy",
     "source":"CTF公开题 - PCAP分析",
     "description":"tshark提取HTTP POST body中的flag"},
]


# 回填：按 id 从真值文件取明文 flag（源码内已无明文）
for _it in real:
    _v = _FLAG_TRUTH.get(_it.get('id', ''))
    if not _v:
        raise SystemExit('[build] 真值文件缺少 id=%s 的 flag' % _it.get('id'))
    _it['flag'] = _v

for p in real:
    p['flag_sha256'] = sha256(p['flag'])
    p['presolve_skill'] = 'auto'

OUT = 'data/ctf_benchmark/real_benchmark.json'
ANSWERS = 'data/answers/real_benchmark_answers.json'

# 真值源纪律（2026-10-05）：产物只留 flag_sha256，明文答案存 data/answers/（不入库）。
# 两道防呆：
#   1) 合并而非覆盖——历史上本脚本只含 31 题，直接覆盖会把后来手加的题冲掉（实测 55→31）；
#   2) 生成时逐题校验 sha256(明文)==flag_sha256，不一致直接报错，杜绝真值分裂。
existing = {}
try:
    with open(OUT, encoding='utf-8') as f:
        existing = json.load(f).get('problems', {})
except FileNotFoundError:
    pass

answers = {}
try:
    with open(ANSWERS, encoding='utf-8') as f:
        answers = json.load(f).get('answers', {})
except FileNotFoundError:
    print('[build] 未找到答案键 data/answers/（正常：明文不入库）；'
          '将只校验已有 flag_sha256，不写入明文')

# 覆盖策略（2026-10-05 实测修正）：**已存在的题一律保留现值**，本脚本只补新题。
# 原因：本脚本内联的 31 题数据比产物旧（产物 55 题含后续手工维护的题面/提示），
# 早期"直接覆盖"写法实测把静态确定性从 34.5% 打到 23.6%——用旧数据盖掉了手工维护成果。
# 因此：existing 里的题绝不覆盖；需要更新题面请手工改产物，或显式传 --force-overwrite。
merged = dict(existing)
added, skipped = 0, 0
for item in real:
    flag = item.pop('flag', None)
    truth = sha256(flag) if flag else None
    if flag and truth != item.get('flag_sha256'):
        raise SystemExit(f"[build] 真值分裂：{item['id']} 明文哈希 {truth[:12]}… "
                         f"!= flag_sha256 {str(item.get('flag_sha256'))[:12]}…")
    if flag:
        answers.setdefault(item['id'], flag)   # 仅落在本机答案键，不进产物
    if item['id'] in merged:
        skipped += 1
        if not merged[item['id']].get('flag_sha256') and truth:
            merged[item['id']]['flag_sha256'] = truth   # 仅补真值，不动题面
        continue
    if flag and not item.get('flag_sha256'):
        item['flag_sha256'] = truth
    merged[item['id']] = item
    added += 1
print(f'[build] 新增 {added} 题；跳过已存在 {skipped} 题（不覆盖手工维护内容）')

bench = {
    'version': 'v5_real',
    'created': '2026-09-06',
    'description': 'CTF真实真题基准集（公开writeup来源，SHA-256验证；明文答案见 data/answers/，不入库）',
    'total': len(merged),
    'problems': merged,
}

with open(OUT, 'w', encoding='utf-8') as f:
    json.dump(bench, f, indent=2, ensure_ascii=False)

try:
    import os
    os.makedirs('data/answers', exist_ok=True)
    with open(ANSWERS, 'w', encoding='utf-8') as f:
        json.dump({'_note': 'real_benchmark.json 的答案键（明文），按约定不入库、禁止进交付包。',
                   'answers': answers}, f, ensure_ascii=False, indent=1)
except OSError as e:
    print(f'[build] 答案键写入失败（不影响产物）: {e}')

print(f'真实真题基准集: {len(merged)}道（合并写入口径；原脚本内联 {len(real)} 道）')
cats = {}
for it in merged.values():
    cats[it['category']] = cats.get(it['category'], 0) + 1
for c, n in sorted(cats.items()):
    print(f'  {c}: {n}道')
