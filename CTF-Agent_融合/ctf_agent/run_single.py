"""单题真跑：走 build_solver(use_mock=False) 的完整生产链路，只跑一道题。

用法： python3 run_single.py <question_id>
环境： CTF_AGENT_LLM_PROVIDER / CTF_AGENT_LLM_API_KEY / CTF_AGENT_USE_REAL_LLM
      CTF_SANDBOX_BACKEND=docker|subprocess
      CTF_AGENT_SKIP_PRESOLVE=1   （纯 LLM 口径，关掉确定性预解）
      CTF_LOG_LEVEL=DEBUG|INFO    （默认 INFO；DEBUG 会打印工具调用的完整入参/返回）
"""
import asyncio
import json
import logging
import os
import sys
import time

sys.path.insert(0, ".")

QID = sys.argv[1]

from eval.cases import load_questions  # noqa: E402
from run import build_solver  # noqa: E402
from scheduler.task_pool import TaskPool  # noqa: E402

_LEVEL = os.environ.get("CTF_LOG_LEVEL", "INFO").upper()
logging.getLogger().setLevel(getattr(logging, _LEVEL, logging.INFO))

# 2026-11-10：此前只写死 data/questions_real，外部真题（questions_ext /
# questions_ext_cybench / questions_external / questions_ext_L2_pure_reasoning）
# 一共 45+ 道题连生产链路都进不了，等于无法评估真实赛题难度。
# 改为遍历多库；setdefault 保证 questions_real 优先（同 id 以原始池为准）。
LIBS = ["data/questions_real", "data/questions_ext", "data/questions_ext_cybench",
        "data/questions_external", "data/questions_ext_L2_pure_reasoning"]
qs = {}
for _lib in LIBS:
    if not os.path.isdir(_lib):
        continue
    for _q in load_questions(_lib):
        qs.setdefault(_q.id, _q)   # 先到先得：questions_real 优先
if QID not in qs:
    print("NO_SUCH_QUESTION", QID)
    sys.exit(2)
q = qs[QID]

print("QID", q.id, "| category", q.category, "| difficulty", q.difficulty)
print("ATTACHMENTS", [os.path.basename(a) for a in (q.attachments or [])])
print("SANDBOX_BACKEND", os.environ.get("CTF_SANDBOX_BACKEND", "(default subprocess)"))
print("LLM_PROVIDER", os.environ.get("CTF_AGENT_LLM_PROVIDER"), "| USE_REAL", os.environ.get("CTF_AGENT_USE_REAL_LLM"))
for a in (q.attachments or []):
    print("ATT_EXISTS", os.path.basename(a), os.path.exists(a))

skip = os.environ.get("CTF_AGENT_SKIP_PRESOLVE", "0").strip().lower() in ("1", "on", "true", "yes")
print("SKIP_PRESOLVE", skip)
solver = build_solver(use_mock=False, skip_presolve=skip)
t0 = time.time()
out = asyncio.run(TaskPool().run_all([q], solver))[0]
elapsed = round(time.time() - t0, 1)

flag = out.get("flag")
err = out.get("error") or {}
print("ELAPSED_S", elapsed)
print("FLAG", flag)
if err:
    print("ERROR", json.dumps(err, ensure_ascii=False)[:400])
if flag:
    try:
        print("MATCH", q.flag_matches(flag))
    except Exception as exc:  # noqa: BLE001
        print("MATCH_ERROR", type(exc).__name__, exc)
