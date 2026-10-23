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
    3) 解包复核六条硬红线：
       - 包内不得出现 data/ · logs/ · .env · *.db · chat_uploads/ 等运行数据
         （例外：data/ctf_benchmark/ 属可机验的**测试资产**而非运行数据，默认纳入）
       - 包内 config.yaml 必须与 config.share.yaml 逐字节一致（即确认顶替生效）
       - 对 staging 跑 secret_guard.py → 必须 PASS(rc=0)
       - 对 staging 跑 check_line_endings.py → 必须 PASS(rc=0)：.sh 必须 LF
         （CRLF 的 .sh 在 Linux 上会报 $'\r': command not found）、.bat/.ps1 必须 CRLF
       - 对 staging 跑 check_artifact_numbers.py → 必须 PASS(rc=0)：**读回**包内
         .pptx/.docx/.pdf 的可见文本，比对 count_stats 真值。文本门禁看不见这类漂移
         （数字与单位常被拆成两个字符串字面量），只有读回渲染产物才暴露。
       - 对 staging 跑 check_binary_version.py --require-binaries --strict-unchecked
         → 必须 PASS(rc=0)：从 exe 内嵌的 Go buildinfo 读出构建来源，断言 commit ==
         当前 HEAD、无 `+dirty`，并解开 NSIS 安装包对内嵌 payload 再判一遍。
         实测教训：包里曾同时有三份构建（09-04 dirty / 09-07 / 09-30），没有一份
         是当时源码的产物，而文件名与体积完全看不出差别。
    4) 任一红线失败 → 删除成品包并 rc=1（宁可不出包，不可出事）

用法：
    python scripts/make_delivery_package.py                 # 产出 dist/SecAutoMind-<ver>-share.tar.gz
    python scripts/make_delivery_package.py --out x.tar.gz
    python scripts/make_delivery_package.py --list-only      # 只预览将纳入/排除的文件
    python scripts/make_delivery_package.py --keep-staging   # 保留 staging 目录以便排查

退出码：
    0 = 包已生成且六项自验全过
    1 = 自验失败（含真凭证 / 含禁区数据 / 产物数字漂移），成品包已删除
"""
import argparse
import datetime
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
BINARY_VERSION_CHECK = os.path.join(ROOT, "scripts", "check_binary_version.py")
CLEAN_CONFIG = os.path.join(ROOT, "config.share.yaml")

# ── 构建输入件的排除口径 ─────────────────────────────────────────────
# 已下沉为门禁自身的 ALWAYS_EXCLUDE（scripts/check_artifact_numbers.py），此处不再维护
# 第二份清单 —— 曾经两处各写一遍（打包脚本 + 裸跑门禁），是典型的漂移温床。
# 判定标准（不许放宽）：**该文件的可见文字不会到达读者**，且必须有代码/实测背书。
#   · 演示模板版.pptx —— make_template_ppt.py 只克隆其首页全屏背景图，文字不进产物。

# ── 排除：目录名（任一父级命中即整棵剪掉）────────────────────────────
EXCLUDE_DIRS = {
    ".git", ".workbuddy", ".workbuddy-ai", ".atomcode", ".idea", ".vscode",
    # `.workbuddy-ai/`（2026-10-24 补）：AI 协作会话的本地记忆目录，**不是**可交付内容。
    # 实锤风险：`.workbuddy-ai/memory/2026-10-22.md` 里明文记着赛事门户的手机号与密码
    # （为向用户解释「门户账号 ≠ Agent 令牌」而写下的原值）。此前只排除了 `.workbuddy/`，
    # 而 `EXCLUDE_PATH_SUBSTR` 里的 `.workbuddy/` 子串匹配不到 `.workbuddy-ai/`
    # → 下次重打包会把会话记忆连同凭证一起发给评委。
    # 该目录同时是 git 未跟踪状态，本就不属于「仓库交付面」。
    "data", "data_backup_boot", "data_backup_boot2",
    # `scans/`（2026-10-24 补）：staticcheck 等静态扫描的**临时产物**，`.gitignore`
    # 已注明「每次重跑都会变，入仓只会污染 diff」。它不属于交付面：
    # 接收方拿到的是一堆过期扫描快照，既不能复现结论、又容易被误当成"当前基线"。
    "scans",
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

# ── 排除：整棵目录（目录名前缀命中即剪掉；判定标准是「不属于交付语义」）──────
# 与 EXCLUDE_DIRS 分开，因为这里每一条都需要**个案理由**，不是通用缓存目录。
EXCLUDE_DIR_PREFIXES = (
    # 初赛提交包快照（赛题要求①「程序材料」）。本机该目录只剩一份 09-04 的
    # `+dirty` 旧构建：159,051,447 B，占整包 57%，且不含源码这期间修掉的
    # 7 critical + 8 high 依赖漏洞与 presolve 占位符短路（#51/#53）。
    # 决赛包再发一份 = 让评委面对两个互不相同的主程序，且大的那个带已知漏洞。
    # 留档在本地（不删），只是不进交付面。
    "SecAutoMind_提交包_",
)

# ── 排除：单个文件（相对仓库根的精确路径，不做前缀/子树匹配）──────────────
# ⚠️ 2026-10-18 踩坑：最初把它写进「路径前缀」表并按 `p.startswith(r + "/")` 判，
# 结果整棵 `SecAutoMind_PPT/` 被剪掉（母版是目录里的一员，目录本身就是它自己的前缀）
# → 包从 222 MB 掉到 54.6 MB，且下面红线 1b 立刻报「两份母版都不在包里」抓住了它。
# 文件级排除必须**精确匹配**，绝不能拿去做子树判定。
EXCLUDE_REL_FILES = {
    # 视觉母版（`make_template_ppt.py` 的输入）。2026-10-18 实测：与同目录的
    # `闽江御盾•智防矩阵.pptx` **可见文本 24/24 单元完全一致**（同款视觉的副本，
    # 只差 zip 里 3 个字节），两份 54 MB 都在包里 = 107 MB 里有一份是纯重复。
    # 生成器缺件时会自动改用该副本（`_TPL_ALIAS` 兜底，实测实跑产出 421,330 B，
    # 与冻结的「模板版」一致），故排除母版后接收方仍能重生成。
    "SecAutoMind_PPT/演示模板版.pptx",
}

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
    if r in EXCLUDE_DIR_PREFIXES or any(p.startswith(r + "/") for p in EXCLUDE_DIR_PREFIXES):
        return True
    return any(s in r for s in EXCLUDE_PATH_SUBSTR)


_VER_CACHE = None


def _current_ver_bare():
    """当前版本号（去 v 前缀），用于「旧安装包只保留当前版本」的判定。"""
    global _VER_CACHE
    if _VER_CACHE is None:
        _VER_CACHE = read_version().lstrip("vV")
    return _VER_CACHE


def is_excluded_file(rel):
    name = rel.replace("\\", "/").rsplit("/", 1)[-1]
    if name in EXCLUDE_FILE_EXCEPTIONS:
        return False
    if rel.replace("\\", "/") in EXCLUDE_REL_FILES:   # 精确路径，不参与子树判定
        return True
    # 2026-10-10（交付包开箱复核发现）：包内若新旧安装包并存，评委打开会困惑
    # 「到底哪个版本」。故只保留与当前版本同号的 `SecAutoMind-Setup-<当前版本>-x64.exe`，
    # 其余版本的 Setup 安装包一律排除（版本号与 config.share.yaml 的 version 同源，去 v 前缀比较）。
    if name.startswith("SecAutoMind-Setup-") and name.endswith(".exe"):
        return ("Setup-%s-" % _current_ver_bare()) not in name
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


# SHARE_README 里两条「派生事实」行是手写维护的死角（2026-10-18 实测）：
#   · `**构建时间**` 还写着 09-30 的 `344e5bd` / md5 `b339fa5b…` / 89,472,512 B；
#   · `**分发包制作**` 还写着 2026-10-10 / 203.2 MB / **五项**红线（现为六项）。
# 它本身就带一句「重新打包后请同步更新本行」—— 事实是没人更新。凡是「要人手同步」的派生字段
# 必然会过期，故改为**打包时按真实产物重写**（在 staging 里写，改的是要发出去的那一份）。
_FACT_BUILD_RE = re.compile(r"^\*\*构建时间\*\*:.*$", re.M)
_FACT_PACK_RE = re.compile(r"^\*\*分发包制作\*\*:.*$", re.M)


def rewrite_share_readme(staging, n_files):
    """按真实产物重写 SHARE_README 的两条派生事实行；锚点缺失即失败（不静默放过）。"""
    path = os.path.join(staging, "SHARE_README.md")
    if not os.path.isfile(path):
        raise SystemExit("[BLOCK] staging 里没有 SHARE_README.md —— 交付说明缺失，拒绝出包")
    exe = os.path.join(staging, "installer", "secautomind-ai.exe")
    if not os.path.isfile(exe):
        raise SystemExit("[BLOCK] staging 里没有 installer/secautomind-ai.exe，"
                         "无法写入构建事实（先跑 installer/build_installer.py）")

    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import count_stats as cs
    info = cs.read_buildinfo(exe) or {}
    commit = (info.get("commit") or "")[:12]
    built_at = info.get("built_at") or ""
    if len(built_at) == 14 and built_at.isdigit():  # 20261017232921 → 2026-10-17 23:29:21
        built_at = "%s-%s-%s %s:%s:%s" % (built_at[0:4], built_at[4:6], built_at[6:8],
                                          built_at[8:10], built_at[10:12], built_at[12:14])
    dirty = "（⚠️ 脏树构建）" if info.get("dirty") else ""
    md5 = hashlib.md5(open(exe, "rb").read()).hexdigest()
    build_line = ("**构建时间**: %s（exe 内嵌 commit `%s`%s，md5 `%s`，%s B；配方见 "
                  "`installer/build_installer.py`，复验 `python installer/build_installer.py "
                  "--verify-only`）" % (built_at or "未知", commit or "未知", dirty, md5,
                                        format(os.path.getsize(exe), ",")))
    pack_line = ("**分发包制作**: %s（纳入文件 %d 个；六项红线全过：无运行数据 · "
                 "`config.yaml` 由 `config.share.yaml` 顶替 · `secret_guard` rc=0 · "
                 "脚本行尾合规 · 产物数字与真值一致 · 程序材料由当前 HEAD 构建。"
                 "本行与上一行由 `scripts/make_delivery_package.py` 自动写入，勿手改）"
                 % (datetime.date.today().isoformat(), n_files))

    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        text = fh.read()
    for pat, line, what in ((_FACT_BUILD_RE, build_line, "构建时间"),
                            (_FACT_PACK_RE, pack_line, "分发包制作")):
        if not pat.search(text):
            raise SystemExit("[BLOCK] SHARE_README.md 里找不到 `%s` 事实行锚点 —— "
                             "格式被改坏了？请先恢复 `**%s**: ...` 这一行再打包。"
                             % (what, what))
        text = pat.sub(lambda _m, s=line: s, text, count=1)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return build_line, pack_line


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify(package, staging):
    """六条硬红线；返回 (ok, issues, notes)。"""
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

    # 红线 1b：生成器可运行性（2026-10-18）
    # 我们把视觉母版 `演示模板版.pptx` 排出了包（它与 `闽江御盾•智防矩阵.pptx` 可见文本
    # 完全一致，两份 54 MB 重复）。代价是接收方跑 `make_template_ppt.py` 时会走
    # `_TPL_ALIAS` 兜底 —— 一旦哪天连 `闽江御盾•智防矩阵.pptx` 也不在包里，
    # 那条生成链就在交付面上**直接断掉**，而本地测试永远发现不了。
    if not any(r.endswith("SecAutoMind_PPT/演示模板版.pptx") for r in rels):
        if not any(r.endswith("SecAutoMind_PPT/闽江御盾•智防矩阵.pptx") for r in rels):
            issues.append("包里既无 演示模板版.pptx 也无 闽江御盾•智防矩阵.pptx —— "
                          "make_template_ppt.py 无母版可用，接收方无法重生成「模板版」")
        else:
            notes.append("视觉母版以 闽江御盾•智防矩阵.pptx 形式随包（make_template_ppt.py 兜底可跑）")

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

    # 红线 6：交付二进制的来源（2026-10-18 新增，实锤事故驱动）
    # 实测：打包前 installer/ 下同时存在三份不同构建的主程序，没有一份是当前 HEAD 的
    # （09-04 dirty / 09-07 / 09-30），而源码这期间修掉了 7 critical + 8 high 依赖漏洞
    # 与 presolve 占位符短路。文件名与体积都看不出来 —— 只有读 exe 内嵌的 Go buildinfo
    # 才能判定。故对 **staging（真正要发出去的字节）** 跑二进制来源门禁，
    # 并且 --require-binaries：包里一个 exe 都没有也算红（评委拿什么跑？）。
    # 2026-10-18 追加 --forbid-history：历史快照（`*提交包_<日期>*`）出现在 staging 即红。
    # 此前它被「只登记不判」的 HIST 分支放过 —— 于是 09-04 那份 159 MB 的 `+dirty`
    # 构建在交付包里躺了六周，占整包 57%，带着源码期间修掉的 15 个依赖漏洞。
    if os.path.exists(BINARY_VERSION_CHECK):
        # ⚠️ staging 是临时目录、**不是 git 仓库** —— 门禁在里面 `git rev-parse HEAD`
        # 会失败。这不是它该自己猜的事：HEAD 必须由调用方显式传入（本次首跑就踩到，
        # 门禁 fail-closed 报 BLOCK，而非静默放过 —— 行为正确，接线要补）。
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                              capture_output=True, text=True).stdout.strip()
        cmd = [sys.executable, BINARY_VERSION_CHECK, "--root", staging,
               "--require-binaries", "--strict-unchecked", "--forbid-history"]
        if head:
            cmd += ["--head", head]
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="ignore")
        if r.returncode == 0:
            notes.append("check_binary_version -> PASS（包内 exe 均由当前 HEAD 构建）")
        else:
            issues.append("check_binary_version -> BLOCK（rc=%d），包内程序不是当前源码"
                          "构建 / 无法核验" % r.returncode)
            for line in (r.stdout or "").splitlines():
                s = line.strip()
                if s.startswith("·") or "[BLOCK]" in s or "[WARN]" in s:
                    notes.append("  | " + s)
    else:
        issues.append("未找到 scripts/check_binary_version.py，无法自验程序材料来源")

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

    # 派生事实行按真实产物重写（写进 staging，即要发出去的那一份）
    build_line, pack_line = rewrite_share_readme(staging, len(included))
    print("  SHARE_README 事实行已按产物重写")

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
        print("  [PASS] 六项红线全过：无运行数据 · config 顶替生效 · 密钥门禁 rc=0 · "
              "脚本行尾合规 · 产物数字与真值一致 · 程序材料由当前 HEAD 构建")
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
