#!/usr/bin/env bash
# 跑批运行环境安装 + 自检（幂等）。
#
# 为什么需要这个脚本（2026-11-08 实测）：
#   服务器 172.16.222.99 的 /usr/bin/python3 = 3.12.13，却**从未按 pyproject 装过依赖**：
#     · 缺 fastapi  ⇒ 全量门禁**收集期就崩**（web/server.py 导入失败）
#     · 缺 scapy + brotli ⇒ pcap 通道**根本不存在**，而 pyproject 的 pcap extra
#       注释自己写着「语义上应视为必备」
#     · 连 pytest 模块都没装 ⇒ 服务器**从没跑过一次 pytest**，
#       过去所有「服务器全绿」都只是本机绿的推断
#   环境靠手敲 pip install 是补不回来的：下次换机器/重建实例，同样三处又会缺。
#
# 用法：
#   ./setup_runtime_env.sh            # 安装 + 自检
#   PY=/usr/bin/python3 ./setup_runtime_env.sh
#   PIP_INDEX=https://pypi.org/simple ./setup_runtime_env.sh
#
# 退出码：0 = 全部依赖可导入；1 = 仍有缺失（会逐项列出）
#
# ⚠️ Debian/Ubuntu 的 PEP 668 会拦 `pip install`，**连 --user 也拦**。
# 本脚本在系统解释器上自动退到 `--user --break-system-packages`：只写 ~/.local，
# 不碰 /usr/lib/python3/dist-packages。不要在已有 venv 里用后者（无必要且会绕过隔离）。

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE/.." || { echo "FATAL: 无法进入 ctf_agent 目录"; exit 1; }

PY="${PY:-python3}"
PIP_INDEX="${PIP_INDEX:-https://mirrors.cloud.tencent.com/pypi/simple}"

if ! command -v "$PY" >/dev/null 2>&1; then
  echo "FATAL: 找不到解释器 '$PY'（用 PY=... 指定）"
  exit 1
fi

echo "=== 解释器 ==="
"$PY" -c 'import sys; print("%s %d.%d.%d" % (sys.executable, *sys.version_info[:3]))'

# ── 1. requires-python 校验（从 pyproject 读，不写死）──────────────────────────
# 声明与生产不一致过一次（2026-11-08 前写的是 >=3.13，而唯一跑题机器是 3.12），
# 所以这里必须真比，不能只打印一行说明。
"$PY" - <<'PY' || exit 1
import sys, tomllib
spec = tomllib.load(open("pyproject.toml", "rb"))["project"]["requires-python"]
lo = spec.replace(">=", "").strip()
cur = "%d.%d.%d" % tuple(sys.version_info[:3])
if tuple(sys.version_info[:2]) < tuple(int(x) for x in lo.split(".")[:2]):
    sys.exit("FATAL: 解释器 %s 低于 pyproject requires-python=%s" % (cur, spec))
print("requires-python=%s  OK（当前 %s）" % (spec, cur))
PY

# ── 2. 依赖清单从 pyproject 生成（避免脚本里的清单和 pyproject 漂移）──────────
DEPS="$("$PY" - <<'PY'
import tomllib
p = tomllib.load(open("pyproject.toml", "rb"))["project"]
deps = list(p.get("dependencies") or [])
for grp in ("dev", "pcap"):
    deps += list((p.get("optional-dependencies") or {}).get(grp) or [])
print(" ".join(deps))
PY
)" || { echo "FATAL: 无法解析 pyproject 依赖"; exit 1; }

if [ -z "$DEPS" ]; then
  echo "FATAL: pyproject 里解析出 0 个依赖 —— 解析逻辑失效，拒绝继续"
  exit 1
fi

echo "=== 待满足依赖（核心 + dev + pcap）==="
echo "$DEPS" | tr ' ' '\n' | sed '/^$/d' | sed 's/^/  /'

# ── 3. 安装（先常规，PEP 668 拦截后退到 --user）────────────────────────────────
install_with() {
  # shellcheck disable=SC2086
  "$PY" -m pip install -i "$PIP_INDEX" "$@" $DEPS
}

echo "=== 安装 ==="
if ! install_with >/tmp/_setup_pip.log 2>&1; then
  if grep -qi "externally-managed-environment" /tmp/_setup_pip.log; then
    echo "  [i] 系统解释器受 PEP 668 保护，改走 --user --break-system-packages（只写 ~/.local）"
    if ! install_with --user --break-system-packages >/tmp/_setup_pip.log 2>&1; then
      echo "FATAL: 安装失败，日志末尾："
      tail -20 /tmp/_setup_pip.log
      exit 1
    fi
  else
    echo "FATAL: 安装失败，日志末尾："
    tail -20 /tmp/_setup_pip.log
    exit 1
  fi
fi
echo "  OK（日志 /tmp/_setup_pip.log）"

# ── 4. 自检：逐模块真的 import，不是只看 pip 说 Successfully ───────────────────
# pip 说成功但 import 失败的情况真实存在（ABI/多解释器混装）。
echo "=== 自检（import 级）==="
"$PY" - <<'PY'
import importlib, importlib.metadata as md, sys

# 包名 → 导入名不一致的少数情况。**必须逐个核对**：漏一个就是假红
# （第一版漏了 pillow→PIL，自检把「装好了」报成「缺 pillow」）。
ALIAS = {"pycryptodome": "Crypto", "pillow": "PIL"}
names = ["gmpy2", "pycryptodome", "sympy", "numpy", "pillow", "pydantic",
         "aiohttp", "httpx", "fastapi", "uvicorn", "pygments",
         "pytest", "pytest_timeout", "pytest_asyncio",
         "scapy", "brotli", "zstandard"]
bad, ok = [], []
for n in names:
    mod = ALIAS.get(n, n)
    try:
        importlib.import_module(mod)
        try:
            ver = md.version(n)
        except Exception:
            ver = "?"
        ok.append("%s=%s" % (n, ver))
    except Exception as exc:
        bad.append("%s (%s: %s)" % (n, type(exc).__name__, exc))

print("  OK  " + " ".join(ok))
if bad:
    print("  MISSING:")
    for b in bad:
        print("    - " + b)
    sys.exit(1)
PY
rc=$?

echo
if [ "$rc" -eq 0 ]; then
  echo "环境就绪：$("$PY" -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])')，依赖全部可导入。"
  echo "下一步可跑：$PY -m pytest -q -m \"not slow and not local\""
else
  echo "环境不完整（见上方 MISSING）。"
fi
exit "$rc"
