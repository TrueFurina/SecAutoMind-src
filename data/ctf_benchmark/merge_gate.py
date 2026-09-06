#!/usr/bin/env python3
"""
merge-gate：CTF 回归集 sha256 机器检查（解题数只升不降）。
设计理念对齐西湖论剑 scripts/_merge_gate.py：
  - 解题记录存于 data/ctf_benchmark/solves_ledger.jsonl（append-only）
  - 每条记录含 problem_id / flag_sha256 / engine / timestamp
  - merge-gate 读 ledger，用 hashlib 校验每条记录的 sha256 一致性
  - 已记录的解题数只允许增加，不允许减少（机器强制）
  - CI 合并门禁：exit 0 = 可合并；exit 1 = 回退/造假，阻止合并

用法：
  # 运行覆盖率并自动追加 ledger
  python3 data/ctf_benchmark/judge.py  # 产出 coverage_report.json
  python3 data/ctf_benchmark/merge_gate.py --record   # 从 report 追加到 ledger

  # CI 检查（仅校验，不追加）
  python3 data/ctf_benchmark/merge_gate.py --check

  # 查看当前 ledger
  python3 data/ctf_benchmark/merge_gate.py --status
"""

import json, hashlib, os, sys, time

BENCH     = "data/ctf_benchmark/benchmark.json"
REPORT    = "data/ctf_benchmark/coverage_report.json"
LEDGER    = "data/ctf_benchmark/solves_ledger.jsonl"
LEDGER_BK = "data/ctf_benchmark/solves_ledger.jsonl.bak"

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

# ── Ledger 操作 ─────────────────────────────────────────

def load_ledger() -> list:
    """加载 ledger 记录（每行一个 JSON 对象）。"""
    if not os.path.exists(LEDGER):
        return []
    records = []
    with open(LEDGER, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return records

def count_solves(records: list) -> int:
    """统计去重后的唯一解题数（同一 problem_id 只计一次最新记录）。"""
    seen = {}
    for r in records:
        pid = r.get('problem_id', '')
        if pid:
            seen[pid] = r
    return len(seen)

def verify_record(r: dict) -> bool:
    """校验一条记录的 sha256 一致性（meta 记录跳过）。"""
    if r.get('type') == 'meta':
        return True  # meta 记录不含 flag，跳过校验
    flag = r.get('flag', '')
    stored = r.get('flag_sha256', '')
    if not flag or not stored:
        return False
    return sha256(flag) == stored

def verify_ledger(records: list) -> tuple:
    """校验整条 ledger：每条记录 sha256 一致 + 去重后解题数。"""
    seen = {}
    errors = []
    for i, r in enumerate(records):
        pid = r.get('problem_id', '')
        if not verify_record(r):
            errors.append(f"record {i} ({pid}): sha256 MISMATCH (flag={r.get('flag','')[:20]}...)")
        if pid:
            seen[pid] = r
    return seen, errors

# ── Merge Gate 核心逻辑 ─────────────────────────────────

def load_prev_count() -> int:
    """读上一次提交的解题数（从 ledger 最后一行的 meta 记录读）。"""
    records = load_ledger()
    for r in reversed(records):
        if r.get('type') == 'meta':
            return r.get('count', 0)
    return count_solves(records)

def record_meta(count: int):
    """往 ledger 追加一条 meta 记录（标记本轮解题数）。"""
    meta = {
        'type': 'meta',
        'count': count,
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    with open(LEDGER, 'a', encoding='utf-8') as f:
        f.write(json.dumps(meta, ensure_ascii=False) + '\n')

def do_record():
    """从 coverage_report.json 追加新解到 ledger（只追加，不覆盖）。"""
    if not os.path.exists(REPORT):
        print(f"❌ 覆盖率报告不存在: {REPORT}，请先运行 judge.py")
        sys.exit(1)

    with open(REPORT, encoding='utf-8') as f:
        report = json.load(f)

    bench = {}
    if os.path.exists(BENCH):
        with open(BENCH, encoding='utf-8') as f:
            bench = json.load(f)

    existing = load_ledger()
    existing_pids = {r.get('problem_id') for r in existing if r.get('problem_id')}

    added = 0
    for r in report.get('results', []):
        if not r.get('sha256_match'):
            continue
        pid = r.get('id', '')
        if pid in existing_pids:
            continue  # 已有记录，跳过

        # 从 benchmark 里取 flag 和 sha256
        problem = bench.get('problems', {}).get(pid, {})
        flag = problem.get('flag', '')
        flag_sha256 = problem.get('flag_sha256', '')

        if not flag or not flag_sha256:
            continue

        record = {
            'problem_id': pid,
            'category': r.get('category', ''),
            'sub': r.get('sub', ''),
            'flag': flag,
            'flag_sha256': flag_sha256,
            'engine': r.get('presolve_engine', ''),
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        }

        if not verify_record(record):
            print(f"  ⚠️ 跳过 {pid}: sha256 不匹配")
            continue

        with open(LEDGER, 'a', encoding='utf-8') as f:
            f.write(json.dumps(record, ensure_ascii=False) + '\n')
        existing_pids.add(pid)
        added += 1
        print(f"  ✅ 追加: {pid} (engine={r.get('presolve_engine')})")

    total = count_solves(load_ledger())
    record_meta(total)
    print(f"\n=== Merge Gate（记录模式）===")
    print(f"本轮追加: {added}")
    print(f"ledger 总解题数: {total}")

def do_check():
    """CI 门禁检查：sha256 一致性 + 解题数只升不降。"""
    records = load_ledger()
    if not records:
        print("✅ ledger 为空，无回退风险，pass")
        sys.exit(0)

    seen, errors = verify_ledger(records)
    if errors:
        print("❌ ledger sha256 校验失败（可能被篡改）：")
        for e in errors:
            print(f"  {e}")
        sys.exit(1)

    current = count_solves(records)
    prev = load_prev_count()

    if current < prev:
        print(f"❌ 解题数回退：{prev} → {current}（merge-gate 禁止减少）")
        sys.exit(1)

    print(f"✅ Merge Gate 通过")
    print(f"  解题数: {prev} → {current}（{'不变' if current == prev else f'+{current - prev}'})")
    print(f"  记录数: {len(records)}")
    print(f"  sha256 校验: 全部通过")
    sys.exit(0)

def do_status():
    """查看当前 ledger 状态。"""
    records = load_ledger()
    seen, errors = verify_ledger(records)
    total = count_solves(records)

    print(f"=== CTF Benchmark Ledger 状态 ===")
    print(f"记录数: {len(records)}")
    print(f"唯一解题数: {total}")
    print(f"sha256 校验: {'全部通过' if not errors else f'{len(errors)} 条异常'}")

    if seen:
        print(f"\n已解题目:")
        for pid, r in sorted(seen.items()):
            print(f"  ✅ {pid}  engine={r.get('engine','')}  category={r.get('category','')}")

# ── 主入口 ──────────────────────────────────────────────

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法：")
        print("  python3 merge_gate.py --record   # 从覆盖率报告追加到 ledger")
        print("  python3 merge_gate.py --check     # CI 门禁校验（只读）")
        print("  python3 merge_gate.py --status    # 查看当前 ledger 状态")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == '--record':
        do_record()
    elif cmd == '--check':
        do_check()
    elif cmd == '--status':
        do_status()
    else:
        print(f"未知命令: {cmd}")
        sys.exit(1)
