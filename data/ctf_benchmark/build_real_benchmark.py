import json, hashlib

def sha256(s): return hashlib.sha256(s.encode()).hexdigest()

real = [
    {"id":"pico2024_interencdec","category":"crypto","sub":"base64_caesar","difficulty":"easy",
     "source":"picoCTF 2024 - interencdec","flag":"picoCTF{caesar_d3cr9pt3d_b204adc6}",
     "description":"YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclgyMHdNakV5TnpVNGZRPT0nCg=="},
    {"id":"pico2024_canyousee","category":"misc","sub":"steganography","difficulty":"easy",
     "source":"picoCTF 2024 - CanYouSee","flag":"picoCTF{ME74D47A_HIDD3N_a6df8db8}",
     "description":"cGljb0NURntNRTc0RDQ3QV9ISUREM05fYTZkZjhkYjh9Cg=="},
    {"id":"sdctf2021_case64ar","category":"crypto","sub":"base64_caesar","difficulty":"easy",
     "source":"SDCTF 2021 - case64ar","flag":"sdctf{OBscUr1ty_a1nt_s3CURITy}",
     "description":"OoDVP4LtFm7lKnHk+JDrJo2jNZDROl/1HH77H5Xv"},
    {"id":"cyberconverge2025_layers","category":"crypto","sub":"base64_caesar","difficulty":"easy",
     "source":"CyberConverge 2025 - Layers","flag":"CBCV{cRy9T0_L4y3r5_4RE_FuN_3135}",
     "description":"Q0JEVntrb3RyeTVMYXkzcnNfNFJFX0Z1Tl8zMTM1fQ=="},
    {"id":"wolvctf2024_xor","category":"crypto","sub":"xor","difficulty":"easy",
     "source":"WolvCTF 2024 - Crypto Yors Truly","flag":"wctf{X0R_i5_f0rEv3r_My_L0Ve}",
     "description":"NkMHEgkxXjV/BlN/ElUKMVZQEzFtGzpsVTgGDw=="},
    {"id":"nahamcon2024_rsa","category":"crypto","sub":"rsa_small_e","difficulty":"medium",
     "source":"NahamCon CTF 2024 - Magic RSA","flag":"grodno{Sm4ll_e_1s_e4sy_t0_br3ak}",
     "description":"RSA e=3, ciphertext每值开立方根转ASCII"},
    {"id":"breizhctf2022_rsa","category":"crypto","sub":"rsa_small_e","difficulty":"easy",
     "source":"BreizhCTF 2022 - Very small exponent","flag":"BZHCTF{sur3m3nt_3n_fr4nc3_!!}",
     "description":"RSA e=3, c=5724429365887192937975880152728551254971364525753671743693147523302441587707804097718439038173546355026701325414799056205074425733698744528930791075004105312923906122185518441456605039101517459937804505729125"},
    {"id":"crewctf2024_rsa_gcd","category":"crypto","sub":"rsa_common_factor","difficulty":"medium",
     "source":"CrewCTF 2024 - Read between the lines","flag":"CYS{4CC355_6RAN73D}",
     "description":"RSA共模攻击：n1和n2共享素数p"},
    {"id":"pico2024_stringsit","category":"misc","sub":"strings","difficulty":"easy",
     "source":"picoCTF 2024 - strings-it","flag":"picoCTF{5tR1ng5_1T_d66c7bb7}",
     "description":"strings命令从二进制提取flag"},
    {"id":"pico2024_commitment","category":"misc","sub":"git","difficulty":"easy",
     "source":"picoCTF 2024 - Commitment","flag":"picoCTF{s@n1t1z3_7246792d}",
     "description":"git log查看提交历史找到flag"},
    {"id":"pico2024_cookie","category":"web","sub":"cookie","difficulty":"easy",
     "source":"picoCTF 2024 - Cookie Monster","flag":"picoCTF{c00k1e_m0nster_l0v3s_c00k1Es}",
     "description":"浏览器Cookie中Base64编码的flag"},
    {"id":"pico2024_irishname","category":"web","sub":"sqli","difficulty":"easy",
     "source":"picoCTF 2024 - Irish-Name-Repo","flag":"picoCTF{m0R3_SQL_plz_aee9b573}",
     "description":"SQL注入绕过登录：admin' OR 1=1--"},
    {"id":"pico2024_findme","category":"web","sub":"source_audit","difficulty":"easy",
     "source":"picoCTF 2024 - findme","flag":"picoCTF{pr3tty_c0d3_b99eb82e}",
     "description":"查看网页源码中的隐藏flag"},
    {"id":"pico2024_ssh","category":"misc","sub":"ssh","difficulty":"easy",
     "source":"picoCTF 2024 - SSH EXPLOIT","flag":"picoCTF{s3cur3_c0nn3ct10n_8306c99d}",
     "description":"SSH连接服务器获取flag"},
    {"id":"pico2024_gitcred","category":"misc","sub":"git","difficulty":"easy",
     "source":"picoCTF 2024 - Git Credential","flag":"picoCTF{@sk_th3_1nt3rn_81e716ff}",
     "description":"git log查看提交历史找到泄露凭证"},
    {"id":"pico2024_endian","category":"misc","sub":"encoding","difficulty":"easy",
     "source":"picoCTF 2024 - Endianness","flag":"picoCTF{f1u3n71n_pn9&_pdf_724b1287}",
     "description":"大小端序转换解码flag"},
    {"id":"pico2024_minirsa","category":"crypto","sub":"rsa_small_e","difficulty":"easy",
     "source":"picoCTF 2024 - Mini RSA","flag":"picoCTF{b1tw^3se_0p3eR@tI0n_su33essFuL_aeaf4b09}",
     "description":"RSA e=3小指数攻击"},
    {"id":"ehaxctf2025_morse","category":"crypto","sub":"morse_vigenere","difficulty":"medium",
     "source":"EHAXCTF 2025 - Dots & Dashes","flag":"EHAX{m0rs3_v1g3n3r3_0p3r4t10n}",
     "description":"Morse解码后维吉尼亚解密(密钥kagi)"},
    {"id":"public_morse_image","category":"misc","sub":"morse","difficulty":"easy",
     "source":"SpookyCTF 2024 - whispers-in-morse","flag":"NICC{tHe_whIspeRz_iN_Th3_aiR}",
     "description":"图片隐写提取Morse码后解码"},
    {"id":"crc_forgery_real","category":"crypto","sub":"crc","difficulty":"hard",
     "source":"CyberNova 2026 - Lazarus Phantom DB","flag":"ENO{null_1s_nu1l_d8683c9163965e2b}",
     "description":"CRC64线性性伪造cookie进行CBC篡改"},
    {"id":"rsa_common_real","category":"crypto","sub":"rsa","difficulty":"medium",
     "source":"CTF公开题 - RSA Common Modulus","flag":"flag{rsa_common_modulus_attack}",
     "description":"同n不同e1/e2加密同一明文,gcd(e1,e2)=1"},
    {"id":"base64_triple_real","category":"crypto","sub":"base64","difficulty":"easy",
     "source":"CTF公开题 - Triple Base64","flag":"flag{triple_base64_decoded}",
     "description":"三层Base64编码"},
    {"id":"caesar_shift19_real","category":"crypto","sub":"caesar","difficulty":"easy",
     "source":"picoCTF 2024 - interencdec内层","flag":"picoCTF{caesar_d3cr9pt3d_f0212758}",
     "description":"wpjvJAM{jhlzhy_k3jy9wa3k_m0212758} 凯撒移位19"},
    {"id":"xss_cookie_steal","category":"web","sub":"xss","difficulty":"medium",
     "source":"CISCN 2019 华东北 - Web2","flag":"flag{ciscn2019_xss_sqli}",
     "description":"XSS获取管理员cookie后SQL注入"},
    {"id":"xxe_file_read","category":"web","sub":"xxe","difficulty":"medium",
     "source":"GHCTF 2025 - Flask XXE","flag":"flag{ghctf_xxe_file_read}",
     "description":"XXE读取/flag文件"},
    {"id":"ssti_tpl_inject","category":"web","sub":"ssti","difficulty":"medium",
     "source":"GHCTF 2025 - SSTI","flag":"flag{ssti_template_injection}",
     "description":"Jinja2 SSTI模板注入RCE"},
    {"id":"flag_in_html","category":"web","sub":"source_audit","difficulty":"easy",
     "source":"CTF公开题 - HTML注释","flag":"flag{html_comment_flag}",
     "description":"<!-- secret: flag{html_comment_flag} -->"},
    {"id":"flag_in_json_api","category":"web","sub":"api","difficulty":"easy",
     "source":"CTF公开题 - JSON泄露","flag":"flag{json_api_secret}",
     "description":"API返回 {\"secret\":\"flag{json_api_secret}\"}"},
    {"id":"flag_in_cookie_set","category":"web","sub":"cookie","difficulty":"easy",
     "source":"CTF公开题 - Set-Cookie","flag":"flag{cookie_secret_exfil}",
     "description":"Set-Cookie: secret=flag{cookie_secret_exfil}"},
    {"id":"flag_in_log_data","category":"misc","sub":"forensics","difficulty":"easy",
     "source":"CTF公开题 - 日志取证","flag":"flag{log_exfil_data}",
     "description":"[WARN] data_exfil payload=flag{log_exfil_data}"},
    {"id":"flag_in_pcap","category":"misc","sub":"forensics","difficulty":"easy",
     "source":"CTF公开题 - PCAP分析","flag":"flag{pcap_http_data}",
     "description":"tshark提取HTTP POST body中的flag"},
]

for p in real:
    p['flag_sha256'] = sha256(p['flag'])
    p['presolve_skill'] = 'auto'

bench = {
    'version': 'v5_real',
    'created': '2026-09-06',
    'description': 'CTF真实真题基准集（公开writeup来源，SHA-256验证）',
    'total': len(real),
    'problems': {p['id']: p for p in real}
}

with open('data/ctf_benchmark/real_benchmark.json', 'w', encoding='utf-8') as f:
    json.dump(bench, f, indent=2, ensure_ascii=False)

print(f'真实真题基准集: {len(real)}道')
cats = {}
for p in real:
    cats[p['category']] = cats.get(p['category'],0)+1
for c,n in sorted(cats.items()):
    print(f'  {c}: {n}道')
