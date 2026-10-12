import json, re

d = json.load(open('data/ctf_benchmark/real_benchmark.json', encoding='utf-8'))
ps = d['problems']
hit = {'base64_triple_real','breizhctf2022_rsa','caesar_shift19_real','cyberconverge2025_layers',
       'ehaxctf2025_morse','flag_in_cookie_set','flag_in_html','flag_in_json_api','flag_in_log_data',
       'nahamcon2024_rsa','pico2024_canyousee','pico2024_endian','pico2024_interencdec','rail_fence_basic',
       'rsa_common_factor','rsa_common_real','rsa_fermat_small','sdctf2021_case64ar','vigenere_known_key'}

b64 = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
hexblob = re.compile(r'\b(?:[0-9a-fA-F]{2}){20,}\b')
rsa = re.compile(r'\b(?:n|e|c|p|q|d)\s*[=:]\s*')
kv = re.compile(r'[=:]\s*["\']?[A-Za-z0-9+/]{6,}')

signals = []
for k, v in ps.items():
    if k in hit:
        continue
    desc = v.get('description') or ''
    low = desc.lower()
    found = []
    if b64.search(desc):
        found.append('base64-blob')
    if hexblob.search(desc):
        found.append('hexblob')
    if rsa.search(desc):
        found.append('rsa-param')
    if any(w in low for w in ['cipher','encrypt','decrypt','xor','rot','caesar','vigenere',
                              'rail','base64','hex','rsa','md5','sha','flag{','password','secret']):
        if kv.search(desc) or 'flag{' in low:
            found.append('kw+value')
    if found:
        signals.append((k, v.get('category'), found, desc[:220]))

print('含可解信号的 MISS 题:', len(signals))
for k, cat, f, desc in signals:
    print('==', k, 'cat=', cat, 'sig=', f)
    print('   ', desc)
    print('---')

# 另外统计 MISS 平均描述长度与是否含任何数字
lens = [len(v.get('description') or '') for k, v in ps.items() if k not in hit]
print('MISS 描述长度: min=%d max=%d avg=%.1f' % (min(lens), max(lens), sum(lens)/len(lens)))
print('MISS 含数字的描述数:', sum(1 for k, v in ps.items()
      if k not in hit and any(ch.isdigit() for ch in (v.get('description') or ''))))
