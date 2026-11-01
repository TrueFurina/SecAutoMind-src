#!/usr/bin/env bash
# backup_wip.sh — 一键备份「历史 + 未提交改动 + 未跟踪文件」
#
# 为什么需要（2026-11-02 排查）：
#   本仓库长期有 100+ 个并行会话在途改动（当时 113 个已跟踪 + 160 个未跟踪），
#   而 git bundle 只含**已提交**内容。一条 `git checkout -- .` 或一次误操作，
#   未提交部分就没了，且没有任何备份机制。
#
# 产出（默认 /d/backup）：
#   SecAutoMind-<日期>.bundle        全部分支/tag 的完整历史（git bundle --all）
#   wip-tracked-<日期>.patch         已跟踪文件的未提交改动（git diff HEAD）
#   wip-untracked-<日期>.tar.gz      未跟踪文件（含未入库的新文档/数据）
#
# 恢复：
#   git clone SecAutoMind-<日期>.bundle 恢复目录   # 历史
#   git apply wip-tracked-<日期>.patch             # 改动（在有 .git 的树里）
#   tar xzf wip-untracked-<日期>.tar.gz            # 未跟踪文件
#
# 用法：bash scripts/backup_wip.sh [输出目录]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-/d/backup}"
DAY="$(date +%Y%m%d)"
mkdir -p "$OUT" || { echo "无法创建 $OUT"; exit 2; }

cd "$ROOT" || exit 2
echo "仓库: $ROOT"
echo "输出: $OUT"
echo

# 1) 完整历史
if git bundle create "$OUT/SecAutoMind-$DAY.bundle" --all >/dev/null 2>&1; then
    echo "[OK]   历史包  SecAutoMind-$DAY.bundle  $(du -h "$OUT/SecAutoMind-$DAY.bundle" | cut -f1)"
else
    echo "[FAIL] 历史包创建失败"; exit 1
fi

# 2) 已跟踪文件的未提交改动
git diff HEAD > "$OUT/wip-tracked-$DAY.patch" 2>/dev/null
if [ -s "$OUT/wip-tracked-$DAY.patch" ]; then
    n=$(git status --porcelain | grep -vc '^??' || true)
    echo "[OK]   改动补丁 wip-tracked-$DAY.patch  $(du -h "$OUT/wip-tracked-$DAY.patch" | cut -f1)  ($n 个文件)"
else
    echo "[SKIP] 无已跟踪改动"
fi

# 3) 未跟踪文件（.gitignore 命中的不在此列，它们本来就不该入库）
# 清单保留在输出目录，作为「这次备份到底包含了什么」的凭据（不删，便于事后核对）
LIST="$OUT/wip-untracked-$DAY.list"
git status --porcelain | grep '^??' | sed 's/^?? //' | tr -d '"' > "$LIST"
if [ -s "$LIST" ]; then
    if tar czf "$OUT/wip-untracked-$DAY.tar.gz" -T "$LIST" 2>/dev/null; then
        echo "[OK]   未跟踪   wip-untracked-$DAY.tar.gz  $(du -h "$OUT/wip-untracked-$DAY.tar.gz" | cut -f1)  ($(wc -l < "$LIST") 项)"
    else
        echo "[WARN] 未跟踪打包部分失败（可能有文件被占用），包仍可用"
    fi
else
    echo "[SKIP] 无未跟踪文件"
fi

echo
echo "备份完成：$OUT"
echo "注意：未提交内容只是**快照**，不是提交。真正安全仍靠及时 commit + push。"
