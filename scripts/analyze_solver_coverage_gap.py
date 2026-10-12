# -*- coding: utf-8 -*-
"""分析注册求解器与基准集覆盖差距（只读分析）。"""
import json
import re
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(BASE)

src = open('internal/ctfplatform/solver_registry.go', encoding='utf-8').read()
names = set(re.findall(r'Name:\s*"([a-z0-9_]+)"', src))
print('注册求解器:', len(names))

covered = set()
for f in ['data/ctf_benchmark/real_benchmark.json',
          'data/ctf_benchmark/execution_benchmark.json',
          'data/ctf_benchmark/web_benchmark.json']:
    if not os.path.exists(f):
        print('缺文件:', f)
        continue
    doc = json.load(open(f, encoding='utf-8'))
    for k, v in doc.get('problems', {}).items():
        for key in ('presolve_skill', 'engine', 'skill'):
            if v.get(key):
                covered.add(v[key])

for f in ['data/ctf_benchmark/real_coverage_report.json',
          'data/ctf_benchmark/execution_coverage_report.json']:
    if not os.path.exists(f):
        continue
    doc = json.load(open(f, encoding='utf-8'))
    for r in doc.get('results', []):
        if r.get('engine'):
            covered.add(r['engine'])

print('基准集出现过的 skill/engine:', len(covered))
unc = sorted(names - covered)
print('无基准集覆盖的求解器 (%d):' % len(unc))
for u in unc:
    print(' ', u)
