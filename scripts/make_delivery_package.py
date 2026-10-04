#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SecAutoMind 交付包制作 + 自验（打包红线自动把关）

背景（2026-09-11 质检）：
    仓库根目录的 config.yaml 是**本地真实运行配置**——含 2 把真实 key（千问 ws 通道、
    飞书 app_secret），被 .gitignore 排除、不进 git，却**会被整目录打包带进交付 zip**。
    旧流程靠人肉记得 `tar --exclude=config.yaml`，漏写一次就泄露凭证
    （终检清单 §A-3「不含真实密钥」在 09-05 提交时并未勾选，这条路径从未被机验锁死）。

本脚本把「排除 → 打包 → 自验」固化成一条命令，且**自验用真实交付物**：
    1) 构建干净 staging：按排除清单复制，并用 config.share.yaml（纯 ${ENV} 占位、零真 key）
       顶替 config.yaml，保证接收方开箱即用
    2) 打包为 tar.gz
    3) 解包复核五条硬红线：
       - 包内不得出现 data/ · logs/ · .env · *.db · chat_uploads/ 等运行数据
         （例外：data/ctf_benchmark/ 属可机验的**测试资产**而非运行数据，默认纳入）
       - 包内 config.yaml 必须与 config.share.yaml 逐字节一致（即确认顶替生效）
       - 对 staging 跑 secret_guard.py → 必须 PASS(rc=0)
       - 对 staging 跑 check_line_endings.py → 必须 PASS(rc=0)：.sh 必须 LF
         （CRLF 的 .sh 在 Linux 上会报 $'\r': command not found）、.bat/.ps1 必须 CRLF
       - 对 staging 跑 check_artifact_numbers.py → 必须 PASS(rc=0)：**读回**包内
         .pptx/.docx/.pdf 的可见文本，比对 count_stats 真值。文本门禁看不见这类漂移
         （数字与单位常被拆成两个字符串字面量），只有读回渲染产物才暴露。
    4) 任一红线失败 → 删除成品包并 rc=1（宁可不出包，不可出事）

用法：
    python scripts/make_delivery_package.py                 # 产出 dist/SecAutoMind-<ver>-share.tar.gz
    python scripts/make_delivery_package.py --out x.tar.gz
    python scripts/make_delivery_package.py --list-only      # 只预览将纳入/排除的文件
    python scripts/make_delivery_package.py --keep-staging   # 保留 staging 目录以便排查

退出码：
    0 = 包已生成且五项自验全过
    1 = 自验失败（含真凭证 / 含禁区数据 / 产物数字漂移），成品包已删除
"""
import argparse
import fnmatch
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET_GUARD = os.path.join(ROOT, "scripts", "secret_guard.py")
LINE_ENDINGS_CHECK = os.path.join(ROOT, "scripts", "check_line_endings.py")
ARTIFACT_NUMBERS_CHECK = os.path.join(ROOT, "scripts", "check_artifact_numbers.py")
CLEAN_CONFIG = os.path.join(ROOT, "config.share.yaml")

# ── 构建输入件的排除口径 ─────────────────────────────────────────────
# 已下沉为门禁自身的 ALWAYS_EXCLUDE（scripts/check_artifact_numbers.py），此处不再维护
# 第二份清单 —— 曾经两处各写一遍（打包脚本 + 裸跑门禁），是典型的漂移温床。
# 判定标准（不许放宽）：**该文件的可见文字不会到达读者**，且必须有代码/实测背书。
#   · 演示模板版.pptx —— make_template_ppt.py 只克隆其首页全屏背景图，文字不进产物。

# ── 排除：目录名（任一父级命中即整棵剪掉）────────────────────────────
EXCLUDE_DIRS = {
    ".git", ".workbuddy", ".atomcode", ".idea", ".vscode",
    "data", "data_backup_boot", "data_backup_boot2",
    "logs", "chat_uploads", "tmp", "temp", "work",
    "__pycache__", ".pytest_cache", "node_modules", "venv", ".venv",
    "dist", "build", ".build", "target", ".gradle",
    ".upgrade-backup", ".slidep", ".cache", "_archive",
    "NVIDIA Corporation",
}
EXCLUDE_DIR_PREFIXES = ("tmp_recon_",)

# ── 例外：被上面目录规则命中、但属「测试资产」而非「运行数据」的路径 ──────
# data/ 整棵剪掉的初衷是剔除运行数据（conversations.db / 上传件 / 初始密码文件）。
# data/ctf_benchmark/ 是本项目可独立机验的测试资产（冠军差异点「双语言机验基准集」，
# 约 1.3MB、无大二进制），属**证据**而非运行数据，故默认纳入；--no-benchmark 可关闭。
INCLUDE_PATH_EXCEPTIONS = ["data/ctf_benchmark"]

# 可再生的嵌套 .git 工件：依项目自身设计（regen_exec_fixtures.py）
# 「嵌套 .git 不入库，由该脚本再生成」，故不入包；包内已含该再生成脚本。
NESTED_GIT_FIXTURE_DIRS = {"exec_git_repo", "git_cred_repo"}

# ── 排除：文件名模式 ──────────────────────────────────────────────
EXCLUDE_FILE_PATTERNS = [
    "config.yaml", "config.local.yaml", "config.yaml.backup", "config.yaml.bak_*",
    ".env", ".env.*",
    "*.db", "*.db-shm", "*.db-wal", "*.db-journal", "*.sqlite", "*.sqlite3",
    "*.pyc", "*.pyo", "*.log", "*.bak", "*.pem", "*.key", "*.crt", "*.new",
    # 内含**明文机器人凭证**的运维接入指南（如 dingtalk-setup-guide.html 带
    # Client Secret、wecom-setup-guide.html 带回调 Token / EncodingAESKey）。
    # 属内网运维资料，随包外发即等于凭证泄露 —— 与下列复核文档同一处置逻辑。
    "*-setup-guide.html",
    # 内部复核类文档：面向前置作者修订用（如对交付手册的勘误），
    # 不应随交付包发给评委。命名约定见「部署手册_勘误与补充_*.md」。
    "部署手册_勘误*.md", "*_内部复核_*.md",
]
EXCLUDE_FILE_EXCEPTIONS = {".env.example"}

# ── 排除：路径子串（PPT 下划线中间产物等）────────────────────────────
EXCLUDE_PATH_SUBSTR = ("SecAutoMind_PPT/_", ".workbuddy/", "/.git/")

# ── 红线：成品包内绝不允许出现的路径前缀（相对包根）────────────────────
FORBIDDEN_IN_PACKAGE = [
    "data/", "logs/", "chat_uploads/", "tmp/", "tmp_recon_",
    ".env", "config.yaml.backup", ".workbuddy/", ".git/",
]


def _in_include_exception(rel):
    """rel 处于某例外路径之下，或是该例外的祖先目录（需继续下钻才到得了）。"""
    r = rel.replace("\\", "/")
    for exc in INCLUDE_PATH_EXCEPTIONS:
        if r == exc or r.startswith(exc + "/") or exc.startswith(r + "/"):
            return True
    return False


def is_excluded_dir(rel):
    parts = rel.replace("\\", "/").split("/")
    for p in parts:
        if p in EXCLUDE_DIRS or p.startswith(EXCLUDE_DIR_PREFIXES):
            return True
    r = rel.replace("\\", "/")
    return any(s in r for s in EXCLUDE_PATH_SUBSTR)


def is_excluded_file(rel):
    name = rel.replace("\\", "/").rsplit("/", 1)[-1]
    if name in EXCLUDE_FILE_EXCEPTIONS:
        return False
    r = rel.replace("\\", "/")
    if any(s in r for s in EXCLUDE_PATH_SUBSTR):
        return True
    return any(fnmatch.fnmatch(name, pat) for pat in EXCLUDE_FILE_PATTERNS)


def build_staging(staging):
    """把 ROOT 下「该进包」的文件复制到 staging，返回纳入清单。"""
    included = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        rel_dir = os.path.relpath(dirpath, ROOT).replace("\\", "/")
        rel_dir = "" if rel_dir == "." else rel_dir

        keep = []
        for d in dirnames:
            child = f"{rel_dir}/{d}" if rel_dir else d
            if not is_excluded_dir(child):
                keep.append(d)
        dirnames[:] = keep

        for fn in filenames:
            child = f"{rel_dir}/{fn}" if rel_dir else fn
            if is_excluded_file(child):
                continue
            src = os.path.join(dirpath, fn)
            dst = os.path.join(staging, child.replace("/", os.sep))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                shutil.copy2(src, dst)
            except OSError as e:
                print("  [WARN] 复制失败，跳过：%s (%s)" % (child, e))
                continue
            included.append(child)

    # 例外路径：主 walk 把 data/ 整棵剪掉，这里把「测试资产」（机验基准集）单独补进包。
    # 与主 walk 分离实现，确保除例外目录外 data/ 下任何文件都不会被顺带带出。
    for exc in INCLUDE_PATH_EXCEPTIONS:
        exc_abs = os.path.join(ROOT, exc.replace("/", os.sep))
        if not os.path.isdir(exc_abs):
            print("  [WARN] 例外路径不存在，跳过：%s" % exc)
            continue
        for dirpath, dirnames, filenames in os.walk(exc_abs):
            rel_dir = os.path.relpath(dirpath, ROOT).replace("\\", "/")
            dirnames[:] = [d for d in dirnames
                           if d not in NESTED_GIT_FIXTURE_DIRS and d != "__pycache__"]
            for fn in filenames:
                if fn.endswith((".pyc", ".pyo")) or fn == ".env" or fn.startswith(".env."):
                    continue
                rel = "%s/%s" % (rel_dir, fn)
                src = os.path.join(dirpath, fn)
                dst = os.path.join(staging, rel.replace("/", os.sep))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                try:
                    shutil.copy2(src, dst)
                except OSError as e:
                    print("  [WARN] 复制失败，跳过：%s (%s)" % (rel, e))
                    continue
                included.append(rel)

    # 用干净配置顶替 config.yaml（接收方开箱即用；纯 ${ENV} 占位，无真 key）
    if os.path.exists(CLEAN_CONFIG):
        shutil.copy2(CLEAN_CONFIG, os.path.join(staging, "config.yaml"))
        included.append("config.yaml  ← 由 config.share.yaml 顶替")
    return included


def read_version():
    try:
        with open(CLEAN_CONFIG, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                m = re.match(r'\s*version:\s*"?([\w.\-]+)"?', line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return "dev"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify(package, staging):
    """四条硬红线；返回 (ok, issues, notes)。"""
    issues, notes = [], []
    with tarfile.open(package, "r:gz") as tf:
        names = tf.getnames()
    roots = {n.split("/", 1)[0] for n in names}
    if len(roots) != 1:
        issues.append("包内顶层目录不唯一：%s" % sorted(roots)[:5])
    root = sorted(roots)[0]
    rels = [n[len(root) + 1:] for n in names if n.startswith(root + "/") and n != root]
    notes.append("包内条目 %d 个（顶层 %s）" % (len(rels), root))

    # 红线 1：运行数据 / 密钥文件不得入包
    for rel in rels:
        low = rel.lower()
        # 例外路径（如 data/ctf_benchmark）豁免「data/ 禁区」，其它禁区仍然生效
        bads = ([b for b in FORBIDDEN_IN_PACKAGE if b != "data/"]
                if _in_include_exception(rel) else FORBIDDEN_IN_PACKAGE)
        for bad in bads:
            if low.startswith(bad) or low == bad.rstrip("/"):
                issues.append("禁区文件入包：%s" % rel)
                break

    # 红线 2：包内 config.yaml 必须等于 config.share.yaml（顶替生效）
    if not os.path.exists(CLEAN_CONFIG):
        issues.append("缺少 config.share.yaml，未执行干净配置顶替")
    elif "config.yaml" not in rels:
        issues.append("包内未见 config.yaml（顶替未生效）")
    else:
        src_hash = sha256(CLEAN_CONFIG)
        dst_hash = sha256(os.path.join(staging, "config.yaml"))
        if src_hash != dst_hash:
            issues.append("包内 config.yaml 与 config.share.yaml 不一致")
        else:
            notes.append("config.yaml 顶替校验通过（sha256 %s…）" % src_hash[:12])

    # 红线 3：对真实交付内容跑密钥门禁
    if os.path.exists(SECRET_GUARD):
        r = subprocess.run([sys.executable, SECRET_GUARD, "--dir", staging],
                           capture_output=True, text=True, encoding="utf-8", errors="ignore")
        if r.returncode == 0:
            notes.append("secret_guard -> PASS（rc=0）")
        else:
            issues.append("secret_guard -> BLOCK（rc=%d），staging 内仍含真凭证" % r.returncode)
            tail = (r.stdout or "").strip().splitlines()
            for line in tail[:12]:
                if "config" in line or "BLOCK" in line or "类型" in line:
                    notes.append("  | " + line.strip())
    else:
        issues.append("未找到 scripts/secret_guard.py，无法自验")

    # 红线 4：脚本行尾（2026-09-30 新增，实锤缺陷驱动的加固）
    # 本脚本用 shutil.copy2 做**字节级复制**，不走 git 的 autocrlf / .gitattributes
    # eol 过滤器 —— 工作副本的行尾会被原样带进交付包。已对 v1.7.25 成品包开箱复核：
    # run.sh / upgrade.sh 为 CRLF，收件人在 Linux 上 `bash run.sh` 直接报
    # `$'\r': command not found`，对「一键部署」是致命的。
    if os.path.exists(LINE_ENDINGS_CHECK):
        r = subprocess.run([sys.executable, LINE_ENDINGS_CHECK, "--dir", staging],
                           capture_output=True, text=True,
                           encoding="utf-8", errors="ignore")
        if r.returncode == 0:
            notes.append("check_line_endings -> PASS（.sh=LF / .bat,.cmd,.ps1=CRLF）")
        else:
            issues.append("check_line_endings -> BLOCK（rc=%d），包内脚本行尾不合规"
                          % r.returncode)
            for line in (r.stdout or "").strip().splitlines():
                if "[FAIL]" in line or "[BLOCK]" in line:
                    notes.append("  | " + line.strip())
    else:
        issues.append("未找到 scripts/check_line_endings.py，无法自验行尾")

    # 红线 5：产物体检（2026-10-04 新增，实锤缺陷驱动）
    # 依据：答辩 PPT 的统计框曾长期写「90 YAML 工具配方」「270 测试文件」，而同页正文
    # 写「91 工具」「286 测试文件」—— 文本门禁看不见它们（源脚本里数字与单位被拆成两个
    # 字符串字面量 `('90', 'YAML 工具配方')`），只有**读回渲染后的 pptx** 才暴露。
    # 包内 .docx/.pdf 同理。故对 staging 逐个读回并比对 count_stats 真值；漂移即不出包。
    # 构建输入件的排除口径**不在这里维护**：已下沉为门禁自身的 ALWAYS_EXCLUDE
    # （scripts/check_artifact_numbers.py），清单只此一份，避免「打包 vs 裸跑」两处漂移。
    if os.path.exists(ARTIFACT_NUMBERS_CHECK):
        cmd = [sys.executable, ARTIFACT_NUMBERS_CHECK, "--dir", staging]
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="ignore")
        if r.returncode == 0:
            notes.append("check_artifact_numbers -> PASS（构建输入由门禁 ALWAYS_EXCLUDE 排除）")
        else:
            issues.append("check_artifact_numbers -> BLOCK（rc=%d），交付物里的数字与真值"
                          "不符或无法核验" % r.returncode)
            shown = 0
            for line in (r.stdout or "").splitlines():
                s = line.strip()
                if not s:
                    continue
                if "已作废旧口径" in s or "真值=" in s or s.startswith("[FAIL"):
                    notes.append("  | " + s)
                    shown += 1
                    if shown >= 12:
                        notes.append("  | …（其余见 check_artifact_numbers.py 原样输出）")
                        break
    else:
        issues.append("未找到 scripts/check_artifact_numbers.py，无法自验产物数字")

    return (not issues), issues, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None, help="成品包路径（默认 dist/SecAutoMind-<ver>-share.tar.gz）")
    ap.add_argument("--list-only", action="store_true", help="只预览，不打包")
    ap.add_argument("--no-benchmark", action="store_true",
                    help="不纳入 data/ctf_benchmark 机验基准集（默认纳入）")
    # 注：staging 一律保留（本环境批量删除会被安全策略拦截），故不提供清理开关。
    args = ap.parse_args()

    if args.no_benchmark:
        INCLUDE_PATH_EXCEPTIONS.clear()

    ver = read_version()
    default_out = os.path.join(ROOT, "dist", "SecAutoMind-%s-share.tar.gz" % ver)
    out = os.path.abspath(args.out or default_out)

    # staging 放 D 盘（本机 C 盘紧张），失败回落系统临时目录
    tmp_base = os.environ.get("SAM_DELIVERY_TMP", "D:/tmp_sam_delivery")
    try:
        os.makedirs(tmp_base, exist_ok=True)
    except OSError:
        tmp_base = None
    # 每次用唯一 staging 目录：本环境的批量删除（>50 文件）会被安全策略拦截，
    # 复用旧目录会残留上一轮陈旧文件，让「包内容 = 当前源」这个前提失效。
    # 宁可留一个可手动清理的临时目录，也不冒打错包的风险。
    base = tmp_base or os.path.join(ROOT, "tmp")
    os.makedirs(base, exist_ok=True)
    staging = os.path.join(base, "staging-%s-%s" % (ver, time.strftime("%Y%m%d-%H%M%S")))
    os.makedirs(staging, exist_ok=True)

    print("=" * 66)
    print("SecAutoMind 交付包制作 · 版本 %s" % ver)
    print("=" * 66)
    print("  staging: %s" % staging)
    included = build_staging(staging)
    print("  纳入文件 %d 个" % len(included))

    if args.list_only:
        top = sorted({p.split("/")[0] for p in included})
        print("  顶层条目：%s" % ", ".join(top))
        if INCLUDE_PATH_EXCEPTIONS:
            print("  例外纳入：%s（机验基准集）" % ", ".join(INCLUDE_PATH_EXCEPTIONS))
        print("  （--list-only 预览结束，未打包）")
        return 0

    os.makedirs(os.path.dirname(out), exist_ok=True)
    root_name = "SecAutoMind-%s-share" % ver
    print("  打包 -> %s" % out)
    with tarfile.open(out, "w:gz") as tf:
        tf.add(staging, arcname=root_name)

    size_mb = os.path.getsize(out) / (1024 * 1024)
    print("  成品 %.1f MB" % size_mb)

    ok, issues, notes = verify(out, staging)
    print("-" * 66)
    for n in notes:
        print("  · %s" % n)
    if ok:
        print("  [PASS] 五项红线全过：无运行数据 · config 顶替生效 · 密钥门禁 rc=0 · "
              "脚本行尾合规 · 产物数字与真值一致")
        print("  交付包就绪：%s" % out)
    else:
        print("  [BLOCK] 自验失败，已删除成品包：")
        for i in issues:
            print("    ! %s" % i)
        try:
            os.remove(out)
        except OSError:
            pass
    print("  staging 保留于 %s（可手动清理；本环境批量删除会被安全策略拦截）" % staging)
    print("=" * 66)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
