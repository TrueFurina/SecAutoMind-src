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


def main():
    root = ROOT
    if "--dir" in sys.argv:
        root = os.path.abspath(sys.argv[sys.argv.index("--dir") + 1])
    allow_no_fp = "--allow-no-fingerprint" in sys.argv
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
    blocked = bool(real) or fingerprint_block

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
    print("  真实凭证命中     %d" % len(real))
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
