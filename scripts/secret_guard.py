#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SecAutoMind 密钥门禁（打包前/提交前必跑）

背景（2026-09-08 质检发现）：
    项目旧的打包前门禁命令是
        grep -rIl -E "sk-[A-Za-z0-9]{16,}|Bearer [A-Za-z0-9]{16,}" docs/ PPT/
    存在两个致命缺口：
      1. 正则 `sk-[A-Za-z0-9]{16,}` 匹配不到 `sk-ws-H.xxx` —— 第 4 位是连字符即断匹配，
         一把真实存活的千问 key 正是从这个洞漏过去的。门禁失效比没有门禁更危险。
      2. 只扫 docs/ PPT/，完全不扫 config.yaml —— 而 config.yaml 被 .gitignore 排除、
         不进 git 却会进交付 zip，恰恰是最该扫的位置。

本脚本修正这两点，并额外做到：
      - 自动区分「真实凭证」与「占位符/示例/测试假值」，后者不算违规
      - 输出一律打码（只显示前 6 后 4），绝不把完整密钥打到终端或日志
      - 扫磁盘真实文件（含 gitignore 的文件），而不是只扫 git 跟踪文件

用法：
    python scripts/secret_guard.py                  # 人类可读报告
    python scripts/secret_guard.py --json           # 机器可读
    python scripts/secret_guard.py --dir .          # 指定扫描根目录

退出码：
    0 = 无真实凭证命中（可交付）
    1 = 发现真实凭证（禁止打包，必须先轮换/移除）
"""
import os
import re
import sys
import json
import subprocess
import time
import unicodedata
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 扫描的文本后缀（跳过二进制/产物）
TEXT_EXT = {
    ".go", ".py", ".md", ".yaml", ".yml", ".json", ".sh", ".ps1", ".bat",
    ".html", ".htm", ".txt", ".env", ".toml", ".ini", ".cfg", ".conf",
    ".js", ".ts", ".vue", ".tmpl", ".nsi", ".b64", ".csv",
}

# 不扫描的目录（二进制产物 / 第三方 / 工具链 / 版本库）
SKIP_DIRS = {
    ".git", ".workbuddy", "node_modules", "dist", "build", "vendor",
    "__pycache__", ".venv", "venv", "logs", "chat_uploads", "data_backup_boot",
    "data_backup_boot2", "execution", ".idea", ".vscode",
}
SKIP_FILE_SUFFIX = {".exe", ".dll", ".ico", ".png", ".jpg", ".jpeg", ".gif",
                    ".zip", ".7z", ".pdf", ".docx", ".pptx", ".db", ".woff",
                    ".woff2", ".ttf", ".mp4", ".bin", ".so", ".dylib"}
MAX_FILE_BYTES = 5 * 1024 * 1024

# 凭证模式（修正版：前缀后允许连字符/点/下划线，不再被第 4 位连字符截断）
PATTERNS = [
    ("OpenAI式 sk- 前缀", re.compile(r"\bsk[-_][A-Za-z0-9][A-Za-z0-9._\-]{10,}")),
    ("千问 ws 通道 key", re.compile(r"\bsk-ws-[A-Za-z0-9][A-Za-z0-9._\-]{8,}")),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9._\-]{12,}")),
    ("AWS Access Key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{12,}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("PEM 私钥", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    # ⚠️ 2026-09-13：阈值由 {24,} 放宽到 {8,}。原阈值让"8 字符 + 省略号"的真 app_secret
    #    打码片段（6jRyD35H...）完全逃逸。纯数字由 is_placeholder 兜住，不会误报。
    #    负向断言 (?!\.\w) 排除 JS 取值写法（`app_secret: document.getElementById(...)` 
    #    曾被捕获成 `document` 造成误报），但保留省略号（`....` 的次字符不是 \w）。
    ("飞书 app_secret", re.compile(r"app_secret\s*[:=]\s*['\"]?([A-Za-z0-9]{8,})(?!\.\w)")),
    ("Bearer 长令牌", re.compile(r"\bBearer\s+([A-Za-z0-9._\-]{24,})")),
]

# 这些路径下的命中属于测试夹具 / CTF 真题语料，本就该含假凭证，
# 不阻塞交付，但单独列为「可疑」交人工确认，避免真凭证藏在其中被忽略。
SUSPECT_PATH = re.compile(
    r"_test\.go$|data/ctf_benchmark/|/tests?/|/testdata/|_example|\.example",
    re.I,
)

# CTF 真题语料里的 flag 常常长得像凭证（如 picoCTF{@sk_th3_...}），统一判为占位
FLAG_LIKE = re.compile(r"picoCTF\{|flag\{|CTF\{|DASCTF\{", re.I)

# ⚠️ 2026-09-13 事故复盘：曾把整个 scripts/secret_guard_test.py 设为豁免，理由是
#    "测试夹具必须内嵌形似真凭证的样本"。结果该文件里真的被写进了**两枚本项目真凭证**
#    （千问 sk-ws- 前 56 字符、飞书 app_secret 完整 32 字符），豁免让门禁一路报 CLEAN。
#    教训：**豁免会腐化**——被豁免的文件没人再看。
#    现行规则：
#      (1) 测试夹具一律使用构造假值（不含真凭证任何片段）；
#      (2) SELF_EXEMPT 仅表示"该文件的命中不计违规"，但**不阻断真 key 指纹反查**（见下）；
#      (3) 指纹反查是本门禁最强的防线：直接比对"是否包含本项目正在使用的真 key 片段"，
#          与正则形态无关，带省略号打码、Base64、换行拆分都逃不掉。
SELF_EXEMPT = {"scripts/secret_guard_test.py"}

# 真 key 指纹：从 config.yaml / 环境变量读取本项目实际在用的凭证，取前 N 字符当指纹。
# 命中即 BLOCK，且**不受** placeholder / SELF_EXEMPT / SUSPECT_PATH 任何豁免影响。
FINGERPRINT_LEN = 12
FINGERPRINT_SOURCES = ("api_key", "app_secret")

# 显式注入通道（回归测试 / CI 自检用；逗号分隔）
FINGERPRINT_ENV_EXTRA = "SECRET_GUARD_EXTRA_FINGERPRINTS"
# 强制清空指纹来源（仅用于 fail-closed 自检，模拟"读不到真值"的环境）
FINGERPRINT_DISABLE_ENV = "SECRET_GUARD_DISABLE_FINGERPRINTS"
# 固定兜底名单：config.yaml 里以 ${VAR} 引用、但可能不在同机 env 的通道
ENV_FALLBACK_NAMES = (
    "DASHSCOPE_API_KEY", "ARK_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY",
    "MOONSHOT_API_KEY", "SILICONFLOW_API_KEY", "ZHIPU_API_KEY", "QIANFAN_API_KEY",
    "FEISHU_APP_SECRET",
)


def _iter_user_env():
    """读 Windows 用户级环境变量（HKCU\\Environment）。

    背景：WorkBuddy/Git Bash 等 shell 常继承不到 User 级变量，导致 os.environ 为空
    → 指纹库为 0 → 最强防线静默缺席（2026-09-13 复检发现）。此处补上注册表回退。
    非 Windows 返回 {}。
    """
    if os.name != "nt":
        return {}
    try:
        import winreg
    except Exception:
        return {}
    out = {}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                i += 1
                if isinstance(val, str) and val:
                    out[name] = val
    except Exception:
        return {}
    return out


def load_real_fingerprints(root=None):
    """收集"本项目真凭证"的前缀指纹。

    来源（并集）：显式注入 env > config.yaml 明文/`${VAR}` 引用 > 进程 env > HKCU\\Environment。
    返回空集表示**最强防线无法生效** —— 调用方 main() 会据此 fail-closed。
    """
    root = root or ROOT
    if os.environ.get(FINGERPRINT_DISABLE_ENV, "").strip() in ("1", "true", "yes"):
        return set()

    names = set(ENV_FALLBACK_NAMES)
    vals = []

    # 1) 显式注入（测试/自检）
    for v in os.environ.get(FINGERPRINT_ENV_EXTRA, "").split(","):
        v = v.strip()
        if len(v) >= FINGERPRINT_LEN:
            vals.append(v)

    # 2) config.yaml：历史明文路径 + ${VAR} 引用收集
    cfg = os.path.join(root, "config.yaml")
    if os.path.isfile(cfg):
        try:
            with open(cfg, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    m = re.match(r"^\s*(api_key|app_secret)\s*:\s*(\S+)", line)
                    if m:
                        v = m.group(2).strip().strip('"').strip("'")
                        if not v.startswith("${") and not v.startswith("#") and len(v) >= 20:
                            vals.append(v)
                    for ref in re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", line):
                        names.add(ref)
        except Exception:
            pass

    # 3) 进程 env / Windows 用户级 env
    user_env = _iter_user_env()
    for n in sorted(names):
        v = (os.environ.get(n) or user_env.get(n) or "").strip()
        if len(v) < 20 or "://" in v or v.lower() in ("true", "false"):
            continue
        vals.append(v)

    fps = set()
    for v in vals:
        fps.add(v[:FINGERPRINT_LEN])
    return fps


def fingerprint_hit(text, fps):
    """返回 text 中命中的指纹（已打码），无命中返回 None。"""
    if not fps:
        return None
    for fp in fps:
        if fp in text:
            return mask(fp)
    return None


STRONG_PLACEHOLDER = re.compile(
    r"xxxx|XXXX|\bxxx\b|\$\{|YOUR_|your_|REPLACE|replace_me|CHANGE_ME|"
    r"placeholder|PLACEHOLDER|example|EXAMPLE|EXAMPLE\.COM|dummy|DUMMY|"
    r"fake|FAKE|invalid|INVALID|test-key|testkey|<[^>]*>|\[.*填写.*\]|"
    r"待填|占位|示例|请填写|你的",
    re.I,
)

# 省略号截断标记
ELLIPSIS = re.compile(r"\.\.\.")

# 凭证前缀：形似真凭证的头部（用于判定"带省略号的截断串"是否该放行）
CRED_PREFIX = re.compile(r"^(?:sk[-_]|gh[pousr]_|xox[baprs]-|AKIA|ASIA)\S*$")

# 兼容旧名（外部/测试若有引用）
PLACEHOLDER = STRONG_PLACEHOLDER


def mask(s):
    """打码：只保留前 6 与后 4 位，其余用 * 替代。铁律：输出绝不出现完整密钥。"""
    s = s.strip()
    if len(s) <= 12:
        return s[:3] + "*" * max(0, len(s) - 3)
    return s[:6] + "*" * (len(s) - 10) + s[-4:]


def is_placeholder(value):
    """判定是否为占位符/示例（True = 安全，不计违规）。

    ⚠️ 2026-09-13 修正（真实泄露事故）：
        旧版把 `...` 当作**无条件**占位特征，于是
        `<真 key 前 29 字符，此处已脱敏>`（documented 于 docs/质检报告_20260908 事故）
        被判为占位符放行 → 该片段随交付包发给了评委，门禁却报 CLEAN。
        打码串恰恰是「真 key 曾被写进文件」的证据，必须默认报警而非放行。
        新规则：带省略号时，**只有**核心不像凭证（或太短）才豁免。
    """
    if FLAG_LIKE.search(value):
        return True
    if STRONG_PLACEHOLDER.search(value):
        return True
    if value.isdigit():
        return True
    if ELLIPSIS.search(value):
        core = value.rstrip(".")
        if CRED_PREFIX.match(core) and len(core) >= 12:
            return False
        return True
    return False


# ---------------------------------------------------------------------------
# CTF flag 明文门禁（2026-10-25 新增 · 事故 #20）
# ---------------------------------------------------------------------------
# 现状：`data/ctf_benchmark/build_real_benchmark.py` **已被 git 跟踪**且内含 31 条
# 明文 flag（picoCTF{...} 等），而原有 PATTERNS 只盯**凭证**形态，`FLAG_LIKE`
# 更是把"形似 flag"当占位符**放行** —— 于是明文答案从没被任何门禁拦过。
# 当前是外部公开赛事答案，严重性中等；但按同样方式存 1024 / 羊城杯的 flag 就是
# **真泄露**（本项目红线：品牌前缀+花括号形态不得入 PUBLIC 仓）。
#
# 判据与 build_cross_bench.py 的 FLAG_CAND_RE **同构**（纪律：修复器/报表必须与
# 判红门禁共用同一判据实现，避免两套口径）。finditer + group(0)（findall 恒绿的坑）。
#
# 分诊不用手工豁免清单 —— 那玩意在 secret_guard 里已经腐化过一次（见 SELF_EXEMPT
# 上方注释）。改用两个不腐化的判据：
#   ① git 跟踪状态：未跟踪文件命中 = **新泄露**，直接 BLOCK；
#   ② 冻结上限：已跟踪文件的命中总数不得超过 baseline（"只许减不许增"），
#      超了就是有人在历史文件里**新加**了明文。
# 与 build_cross_bench.FLAG_CAND_RE 同源但**更严**（口径差异有意为之，别合并）：
#   - build_cross_bench 用于「题面遮蔽」，宁宽勿窄（多遮蔽无害）；
#   - 这里用于「泄露判红」，必须准（误报洪水会让门禁被当噪音关掉）。
# 实测噪声 100% 是 Go 结构体字面量（`ExecuteRequest{Command: cmd}`、
# `string{"xxe", ...}`、`Message{schema.ToolMessage(...)}`），故内容里禁止
# 引号/冒号/逗号/分号/空格。**不禁止单引号** —— 真 flag 里出现过
# `flag{7h3_p457_c4n'7_b3_70rn_0u7...}`，禁了就漏判。
FLAG_CAND_RE = re.compile(r"([A-Za-z0-9_]{2,})\{[^}\n\":;, ]{4,80}\}")
# 明显占位（遮蔽后的 `前缀{****}`、全等字符、测试空壳）不算明文
FLAG_PLACEHOLDER_RE = re.compile(r"\{\**\}|\{x+\}|\{XXXX\}|\{\.\.\.\}", re.I)
# 可用 SECRET_GUARD_FLAG_BASELINE 覆盖（回归测试必须隔离，别污染真基线）
FLAG_BASELINE = Path(
    os.environ.get("SECRET_GUARD_FLAG_BASELINE")
    or (Path(__file__).resolve().parent / "plaintext_flag_baseline.json"))


def _git_tracked(root: str) -> set[str] | None:
    """返回仓库内已跟踪文件集合；非 git 目录返回 None（调用方必须 fail-closed）。

    必须用 `-z`（或 core.quotepath=false）：默认输出会把非 ASCII 路径转义成
    `"CTF-Agent_\\350\\236\\215..."` 这种带引号的八进制串，与 os.walk 给出的
    真实路径永远对不上 —— 结果整目录（本仓 153 个 skill）被误判成"未入库副本"，
    既漏掉真泄露，又让"未入库 2016 条"这个数字虚高。
    """
    try:
        r = subprocess.run(["git", "-C", root, "-c", "core.quotepath=false", "ls-files", "-z"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=120)
        if r.returncode != 0:
            return None
        return {ln.replace("\\", "/") for ln in (r.stdout or "").split("\0") if ln}
    except Exception:
        return None


def _flag_is_printable(raw: str) -> bool:
    """内容不得含控制字符 —— 排除二进制噪声。

    实测：`.json` 里嵌的 shellcode 字节（`au{H\\x8b\\x95...}`）会被 FLAG_CAND_RE 命中，
    它们不是答案，只是二进制被当文本读出来的乱码。
    """
    body = raw[raw.find("{") + 1: -1]
    if not body:
        return False
    return not any(unicodedata.category(ch) == "Cc" for ch in body)


# 真实赛事品牌前缀（残留在 PUBLIC 仓 = 真泄露）；其余多为自产构造值/题面密文
REAL_BRAND_RE = re.compile(
    r"^(d0g3|DASCTF|picoCTF|VNCTF|ISCTF|XCTF|NCTF|HITB|GXY|ACTF|SUCTF|"
    r"W4ter|MiniL|西湖|虎符)\{", re.I)

# ── 占位符模板 ≠ 答案 ────────────────────────────────────────────────────────
# 判据与 internal/ctfplatform/presolve_registry.go 的 flagPlaceholderRe +
# flagPlaceholderWords **同构**（纪律：引擎与门禁必须共用同一判据，否则引擎已经
# 判定「这不是 flag」的串，门禁还报成「真赛事品牌真泄露」）。
# 实测动机（2026-10-25）：161 条「真赛事品牌」里 53 条是占位符模板
# （`DASCTF{%d-%d}` printf 模板、`DASCTF{init1-init2}` 格式声明、
#  `picoCTF{your_flag_here}`、截断样例 `DASCTF{3792...}`），虚报 +33%。
# 这类串**不含答案**，出现在 PUBLIC 仓不构成泄露；把它们算进最高优先级的
# 「真泄露」队列，只会让真正的 108 条被稀释、排序失真。
PLACEHOLDER_BODY_RE = re.compile(r"(?i)(\binit\d+\b|x{4,}|\.\.\.|\byour|\*{4,}|%[a-z]|\?{2,})")
PLACEHOLDER_WORDS = frozenset({
    "flag", "flags", "flaghere", "yourflag", "yourflaghere", "insertflag",
    "insertflaghere", "putflaghere", "test", "testflag", "example", "sample", "demo",
})


def classify_brand(raw: str) -> str:
    """把一条 flag 外形命中原分为三类：placeholder / real / self。

    只影响**优先级分诊**，不影响「命中」本身：命中数（tracked_hits 上限）仍按
    「像 flag 就算」的宽口径统计，避免放宽判据给自己开后门。
    """
    body = raw[raw.find("{") + 1: -1]
    if PLACEHOLDER_BODY_RE.search(body):
        return "placeholder"
    key = re.sub(r"[^a-z0-9]", "", body.lower())
    if key in PLACEHOLDER_WORDS:
        return "placeholder"
    return "real" if REAL_BRAND_RE.match(raw) else "self"


def scan_plaintext_flags(root: str, tracked: set[str] | None = None):
    """扫描形如 `前缀{内容}` 的 CTF flag 明文。返回 (hits, untracked_hits)。

    hits: [{"file","line","masked","tracked":bool}]
    untracked_hits: 未跟踪文件里的命中（= 新泄露，最严重）
    """
    hits: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in SKIP_FILE_SUFFIX:
                continue
            if ext and ext not in TEXT_EXT and fn not in (".env", "Dockerfile"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(path) > MAX_FILE_BYTES:
                    continue
                # ⚠️ 必须**全文口径**，不能 splitlines 逐行：str.splitlines 按 Unicode
                # 行边界切分（\x0b \x0c \x1c \x1d \x1e \x85 \u2028 \u2029），而正则只禁
                # \n → 含这些字符的 flag 会被逐行口径整条漏掉。实测漏过 3 条。
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except Exception:
                continue
            rel = os.path.relpath(path, root).replace("\\", "/")
            for m in FLAG_CAND_RE.finditer(text):
                raw = m.group(0)
                if FLAG_PLACEHOLDER_RE.search(raw):
                    continue
                if not _flag_is_printable(raw):
                    continue
                lineno = text.count("\n", 0, m.start()) + 1
                is_tracked = (rel in tracked) if tracked is not None else False
                hits.append({
                    "file": rel,
                    "line": lineno,
                    "masked": mask(raw),
                    "tracked": is_tracked,
                    "brand": classify_brand(raw),
                })
    untracked = [h for h in hits if not h["tracked"]]
    return hits, untracked


def evaluate_flag_policy(hits, tracked_set, baseline):
    """明文 flag 的分诊策略（纯函数，便于单测）。

    返回 (block: bool, note: str, n_tracked: int, untracked: list)
    """
    untracked = [h for h in hits if not h["tracked"]]
    n_tracked = len(hits) - len(untracked)
    # 严重度分级：真赛事品牌 = 真泄露；其余多为自产构造值或题面密文，风险低得多
    # 口径纪律：n_real 必须只在 tracked 集合内统计，不能拿"全部 hits"减去"已入库数"
    # ——首版就是这么写的，得出 390 这个假数（真实已入库真赛事仅 105 条）。
    n_real = sum(1 for h in hits if h["tracked"] and h.get("brand") == "real")
    # 占位符模板（printf 模板 / 格式声明 / 截断样例）不是答案，单列出来而不是塞进
    # 「真泄露」——否则最高优先级队列会被假阳性稀释（2026-10-25 实测虚报 33%）。
    n_ph = sum(1 for h in hits if h["tracked"] and h.get("brand") == "placeholder")
    sev = (f"｜真赛事品牌 {n_real} 条（真泄露，优先清）"
           f"／自产构造 {max(n_tracked - n_real - n_ph, 0)} 条"
           f"／占位符模板 {n_ph} 条（非答案）" if n_tracked else "")
    if tracked_set is None:
        # 非 git 目录：无法区分入库/未入库。此时**只有确有命中才 fail-closed** ——
        # 干净目录（如门禁自测用的临时空目录）必须放行，否则 --allow-no-fingerprint
        # 的降级放行语义会被打穿（实测把既有用例搞红过一次）。
        if not hits:
            return (False, "该目录不在 git 仓库中，但无任何明文 flag 命中 → 放行",
                    n_tracked, untracked)
        return (True, f"该目录不在 git 仓库中，无法区分新旧，且含 {len(hits)} 条明文 "
                      f"flag → fail-closed，全部按新泄露处理", n_tracked, untracked)
    if baseline is None:
        return (False,
                f"⚠️ 无冻结基线：已入库文件含明文 flag {n_tracked} 条"
                f"（另有未入库副本 {len(untracked)} 条）{sev}。"
                f"先清理再执行 --freeze-flag-baseline 冻结上限",
                n_tracked, untracked)
    cap = baseline.get("tracked_hits", 0)
    # 真赛事品牌独立卡口（比总数更严）：总数口径存在洗白通道 ——
    # 「删 5 条自产夹具 + 加 5 条真题答案」总数不变，只卡总数就照样放行。
    # 旧基线没有这个键（None）时不阻断，只提示重冻，避免把历史基线判成假红。
    cap_real = baseline.get("real_brand_hits")
    if cap_real is not None and n_real > cap_real:
        return (True, f"真赛事品牌明文 flag {n_real} 条 > 冻结上限 {cap_real} 条 —— "
                      f"新增了真题答案（即使总数 {n_tracked} 未超 {cap} 也必须拦）",
                n_tracked, untracked)
    if n_tracked > cap:
        return (True, f"已入库文件明文 flag {n_tracked} 条 > 冻结上限 {cap} 条 —— "
                      f"有人在历史文件里新加了答案", n_tracked, untracked)
    extra = "" if cap_real is not None else "；⚠️ 基线未记真品牌上限，请重跑 --freeze-flag-baseline"
    return (False, f"已入库历史遗留 {n_tracked} 条（上限 {cap}），未新增"
                   f"{sev}{extra}", n_tracked, untracked)


def load_flag_baseline() -> dict | None:
    try:
        if FLAG_BASELINE.is_file():
            return json.loads(FLAG_BASELINE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def freeze_flag_baseline(root: str, snapshot: str | None = None) -> int:
    """固化明文 flag 上限。

    `snapshot` 非空时，改为在「HEAD + 本次提交文件」的导出快照上测量（快照内
    所有文件都视为已入库）。**这是并发开发下唯一正确的口径**：工作树里常有别的
    会话尚未提交的遮蔽改动，按工作树冻结会让 CI 在干净检出上看到更高数值 →
    门禁假红 → 门禁被绕过（2026-10-25 实际踩过一次）。
    """
    if snapshot:
        snap = os.path.abspath(snapshot)
        if not os.path.isdir(snap):
            print(f"❌ 快照目录不存在：{snap}")
            return 1
        tracked = set()
        for dp, dn, fn in os.walk(snap):
            dn[:] = [d for d in dn if d not in SKIP_DIRS]
            for f in fn:
                tracked.add(os.path.relpath(os.path.join(dp, f), snap).replace(os.sep, "/"))
        hits, _untracked_snap = scan_plaintext_flags(snap, tracked)
        untracked = [h for h in hits if not h["tracked"]]
        basis = (f"上限取 `git archive HEAD` + 本次提交文件 的导出快照（{snap}）实测值，"
                 f"不是当前工作树值 —— 工作树含并发会话未提交的改动。")
    else:
        tracked = _git_tracked(root)
        if tracked is None:
            print("❌ 拒绝固化：该目录不在 git 仓库中，无法区分入库/未入库")
            return 1
        hits, untracked = scan_plaintext_flags(root, tracked)
        basis = "上限取当前工作树实测值（单会话、无并发未提交改动时才可用）。"
    if untracked:
        print(f"⚠️  另有未入库副本 {len(untracked)} 条明文 flag，不计入上限"
              f"（不进 PUBLIC 仓，但 git add 后会变成入库泄露）")
    tracked_hits = [h for h in hits if h["tracked"]]
    per_file: dict[str, int] = {}
    for h in tracked_hits:
        per_file[h["file"]] = per_file.get(h["file"], 0) + 1
    # 真赛事品牌单独成账：只卡总数会留下「删 5 条自产夹具 + 加 5 条真题答案」
    # 的洗白通道（总数不变 → 放行），而真题答案才是唯一真正不可外流的资产。
    real_hits = [h for h in tracked_hits if h.get("brand") == "real"]
    real_files: dict[str, int] = {}
    for h in real_hits:
        real_files[h["file"]] = real_files.get(h["file"], 0) + 1
    data = {
        "_why": "已跟踪历史文件里的 CTF flag 明文冻结上限。只许减不许增："
                "超过此数即视为新泄露并 BLOCK。清一条就重跑本命令下调上限。",
        "frozen_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "root": root,
        "tracked_hits": len(tracked_hits),
        "real_brand_hits": len(real_hits),
        "real_brand_files": real_files,
        "untracked_copies": len(untracked),
        "per_file": per_file,
        # 口径来源必须随基线一起落盘：否则下一个人看到 2519 会以为是工作树实测值，
        # 又按工作树重冻一次，把并发未提交的遮蔽抹掉 → 上限被打回高位。
        "_frozen_basis": basis,
    }
    # 保住人工写下的 `_target` / `_correction_*` 等元数据：每次冻结都重算会把
    # 「为什么是这个数、要降到多少」抹掉，那正是下一次误判的起点。
    for k, v in (load_flag_baseline() or {}).items():
        if k.startswith("_") and k not in data:
            data[k] = v
    FLAG_BASELINE.write_text(json.dumps(data, ensure_ascii=False, indent=1),
                             encoding="utf-8")
    print(f"✅ 已固化明文 flag 上限 {len(tracked_hits)} 条（{len(per_file)} 个文件）→ {FLAG_BASELINE}")
    return 0


def scan_dir(root, fps=None):
    findings = []
    scanned = 0
    if fps is None:
        fps = load_real_fingerprints(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not d.startswith(".") or d == "."]
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in SKIP_FILE_SUFFIX:
                continue
            if ext and ext not in TEXT_EXT and fn not in (".env", "Dockerfile"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(path) > MAX_FILE_BYTES:
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.read().splitlines()
            except Exception:
                continue
            scanned += 1
            for lineno, line in enumerate(lines, 1):
                rel = os.path.relpath(path, root).replace("\\", "/")
                # ① 真 key 指纹反查（最高优先级）：只要出现本项目在用的凭证片段就报警，
                #    与正则形态无关，**不受** placeholder / SELF_EXEMPT / SUSPECT_PATH 影响。
                fp = fingerprint_hit(line, fps)
                if fp:
                    findings.append({
                        "file": rel,
                        "line": lineno,
                        "kind": "真 key 指纹命中",
                        "masked": fp,
                        "placeholder": False,
                        "suspect": False,
                        "forced": True,
                    })
                # ② 形态匹配
                # flag 特征必须看整行：PATTERNS 只截取 `sk_th3...` 片段，
                # 其外的 `picoCTF{` 前缀不在片段内，只看片段会漏判（2026-09-09 实测修复）。
                line_is_flag = bool(FLAG_LIKE.search(line))
                for label, pat in PATTERNS:
                    for m in pat.finditer(line):
                        # 优先取捕获组（例如 app_secret: xxx 只取值，不把字段名算进密钥）
                        raw = m.group(1) if pat.groups and m.group(1) else m.group(0)
                        ph = (is_placeholder(raw) or line_is_flag
                              or rel in SELF_EXEMPT)
                        suspect = (not ph) and bool(SUSPECT_PATH.search(rel))
                        findings.append({
                            "file": rel,
                            "line": lineno,
                            "kind": label,
                            "masked": mask(raw),
                            "placeholder": ph,
                            "suspect": suspect,
                            "forced": False,
                        })
    return scanned, findings


# ── 哈希钉死白名单（2026-10-25 立尺就任第一刀）──────────────────────────
# 背景：全树 21 处 PyCryptodome SelfTest 公开测试向量等假阳性曾长期靠
# 「--no-verify + [注] 留痕」人肉前例绕过（MEMORY 有案）。本机制把它治成机器
# 门禁：豁免必须 (path, 行内容 sha256) 双钉死——行变/挪位即自动失效复红
# （防腐化：本仓历史上有过一次手写豁免清单静默烂掉的教训，见 SELF_EXEMPT 注）。
# 🔴 指纹命中（forced=True）永不豁免——最强防线不设后门。
ALLOWLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "secret_guard_allowlist.json")


def load_allowlist():
    try:
        with open(ALLOWLIST_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _line_sha256(line_text):
    import hashlib
    return hashlib.sha256(
        line_text.strip().encode("utf-8", "replace")).hexdigest()


def allowlist_exempt(finding, root):
    """finding 是否被白名单豁免（path 钉死 + 行内容哈希钉死；forced 永不豁免）。"""
    if finding.get("forced"):
        return None
    rel = finding["file"]
    try:
        with open(os.path.join(root, rel), encoding="utf-8", errors="ignore") as fh:
            lines = fh.read().splitlines()
        text = lines[finding["line"] - 1] if 0 < finding["line"] <= len(lines) else ""
    except Exception:
        return None
    h = _line_sha256(text)
    for e in load_allowlist():
        if e.get("path") == rel and e.get("line_sha256") == h:
            return e
    return None


def audit_allowlist(root):
    """--audit-allowlist：逐条核验白名单仍能命中当前磁盘（腐化检测）。"""
    entries = load_allowlist()
    if not entries:
        print("白名单为空")
        return 0
    # 复用主扫描拿全部 real 命中，再对每个条目找匹配
    _, findings = scan_dir(root)
    fps = load_real_fingerprints(root)
    real = [f for f in findings
            if f.get("forced") or (not f["placeholder"] and not f["suspect"])]
    matched = set()
    for f in real:
        e = allowlist_exempt(f, root)
        if e:
            matched.add((e["path"], e["line_sha256"]))
    stale = 0
    print("=== secret_guard 白名单审计 ===")
    for e in entries:
        key = (e.get("path"), e.get("line_sha256"))
        ok = key in matched
        if not ok:
            stale += 1
        print("  %s %s :: %s" % ("OK  " if ok else "STALE", e.get("path", "?"),
                                 e.get("reason", "")[:40]))
    print("共 %d 条，失效 %d 条" % (len(entries), stale))
    return 1 if stale else 0


def main():
    root = ROOT
    if "--dir" in sys.argv:
        root = os.path.abspath(sys.argv[sys.argv.index("--dir") + 1])
    allow_no_fp = "--allow-no-fingerprint" in sys.argv
    if "--audit-allowlist" in sys.argv:
        return audit_allowlist(root)
    if "--freeze-flag-baseline" in sys.argv:
        snap = None
        if "--basis-snapshot" in sys.argv:
            snap = sys.argv[sys.argv.index("--basis-snapshot") + 1]
        return freeze_flag_baseline(root, snap)
    if "--skip-flag-scan" in sys.argv:
        tracked_set, flag_hits, flag_untracked = set(), [], []
        flag_block, flag_note = False, "已用 --skip-flag-scan 跳过"
        flag_base = None
    else:
        tracked_set = _git_tracked(root)
        flag_hits, flag_untracked = scan_plaintext_flags(root, tracked_set)
        flag_base = load_flag_baseline()
        # 只看**已入库**文件：未跟踪副本不进 PUBLIC 仓，不构成入库泄露，
        # 但一旦 git add 就会 —— 所以它们单列告警，不计入冻结上限。
        flag_block, flag_note, _n, flag_untracked = evaluate_flag_policy(
            flag_hits, tracked_set, flag_base)
    scanned, findings = scan_dir(root)

    real = [f for f in findings
            if f.get("forced") or (not f["placeholder"] and not f["suspect"])]
    suspect = [f for f in findings if f["suspect"] and not f.get("forced")]
    placeholder = [f for f in findings
                   if f["placeholder"] and not f.get("forced")]
    forced = [f for f in findings if f.get("forced")]
    fps = load_real_fingerprints(root)

    # fail-closed：指纹库为空 = 最强防线（真 key 反查）缺席 → 默认拒绝放行。
    # 依据 2026-09-13 深度复检：旧实现只打一行小字仍给 PASS，与 09-08 / 09-13 两次
    # 门禁失效同构（"防线缺席"被当成"防线通过"）。CI 等确实无真值的环境须显式
    # 传 --allow-no-fingerprint 降级，并接受"仅形态匹配"的人工复核义务。
    fingerprint_degraded = not fps
    fingerprint_block = fingerprint_degraded and not allow_no_fp
    # 白名单豁免（哈希钉死；forced 永不豁免）——豁免数进报告，数字可审计
    wl_real, whitelisted = [], []
    for f in real:
        e = allowlist_exempt(f, root)
        if e:
            whitelisted.append((f, e))
        else:
            wl_real.append(f)
    real = wl_real
    blocked = bool(real) or fingerprint_block or flag_block

    if "--json" in sys.argv:
        print(json.dumps({
            "scanned_files": scanned,
            "fingerprints_loaded": len(fps),
            "fingerprint_degraded": fingerprint_degraded,
            "fingerprint_block": fingerprint_block,
            "real_findings": real,
            "forced_findings": forced,
            "suspect_findings": suspect,
            "placeholder_findings": len(placeholder),
            "plaintext_flag_hits": len(flag_hits),
            "plaintext_flag_untracked": len(flag_untracked),
            "plaintext_flag_block": flag_block,
            "plaintext_flag_note": flag_note,
            "verdict": "BLOCK" if blocked else "PASS",
        }, ensure_ascii=False, indent=2))
        return 1 if blocked else 0

    print("=" * 66)
    print("SecAutoMind 密钥门禁 · 扫描根目录 %s" % root)
    print("=" * 66)
    print("  已扫描文本文件   %d" % scanned)
    print("  真 key 指纹库     %d 条%s" % (
        len(fps), "" if fps else "（⚠️ 未加载到真 key：config.yaml / 进程 env / HKCU 用户级 env 均取不到）"))
    print("  占位符/示例命中  %d（判定安全，不计违规）" % len(placeholder))
    print("  可疑命中         %d（测试夹具/CTF 语料，不阻塞但请人工确认）" % len(suspect))
    print("  真实凭证命中     %d（另有 %d 条白名单豁免：--audit-allowlist 可审计）"
          % (len(real), len(whitelisted)))
    print("-" * 66)
    if real:
        print("  [BLOCK] 发现真实凭证，禁止打包交付：\n")
        for f in real:
            mark = " 🔴指纹" if f.get("forced") else ""
            print("    %s:%d%s" % (f["file"], f["line"], mark))
            print("      类型: %s" % f["kind"])
            print("      值(已打码): %s" % f["masked"])
        print("\n  处理顺序：")
        print("    1) 到对应平台【轮换/revoke】该凭证（泄露过的 key 不可继续使用）")
        print("    2) 改为环境变量注入（本项目 env 优先级高于 yaml）")
        print("    3) 重跑本脚本直到 PASS，再打包")
        if forced:
            print("\n  ⚠️ 上述带 🔴指纹 的命中 = 文档/代码里出现了**本项目正在用的真 key 片段**。")
            print("     这不是'打码示例'，而是真凭证泄露：即使只泄露前 12 字符也应视为已泄露，")
            print("     必须轮换该 key，并把片段替换为完全脱敏的文本（如 `<redacted>`）。")
    elif fingerprint_block:
        print("  [BLOCK] 真 key 指纹库为空 —— 最强防线（真 key 反查）未生效，拒绝放行。")
        print("    当前环境读不到 config.yaml 明文，也读不到相关环境变量")
        print("    （含 Windows 用户级 HKCU\\Environment），无法判定「真实凭证是否落盘」。")
        print("    处理顺序：")
        print("      1) 确认 User 级环境变量已设置（DASHSCOPE_API_KEY / FEISHU_APP_SECRET 等）；")
        print("      2) Shell 继承不到时，改用能读到用户级变量的进程重跑（如 PowerShell）；")
        print("      3) CI 等确无真值的环境须显式加 --allow-no-fingerprint（降级为仅形态匹配，需人工复核）。")
    elif fingerprint_degraded:
        print("  [PASS·降级] 未发现真实凭证；但指纹库为空且已显式 --allow-no-fingerprint，")
        print("    本次仅经形态匹配、**未启用真 key 指纹反查**，请人工复核后再放行。")
    else:
        print("  [PASS] 未发现真实凭证，且真 key 指纹反查已生效，可进入打包流程。")
    print("-" * 66)
    print("  CTF flag 明文   %d 条（未跟踪 %d 条）%s" % (
        len(flag_hits), len(flag_untracked), "❌" if flag_block else "✅"))
    print("     %s" % flag_note)
    if flag_untracked:
        print("  ⚠️  未入库副本里的明文 flag %d 条（不进 PUBLIC 仓，故不阻断；"
              "但 git add 后即刻变成入库泄露）：" % len(flag_untracked))
        for f in flag_untracked[:8]:
            print("    %s:%d  %s" % (f["file"], f["line"], f["masked"]))
        if len(flag_untracked) > 8:
            print("    ... 另有 %d 条" % (len(flag_untracked) - 8))
        print("    处置：改成只存 sha256（明文放 gitignore 的本地文件），或从题面里遮蔽。")
    if suspect:
        print("\n  可疑命中清单（测试/语料，通常无需处理）：")
        for f in suspect[:15]:
            print("    %s:%d  %s  %s" % (f["file"], f["line"], f["kind"], f["masked"]))
        if len(suspect) > 15:
            print("    ... 另有 %d 条" % (len(suspect) - 15))
    print("=" * 66)
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
