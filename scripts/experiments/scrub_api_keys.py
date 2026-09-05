#!/usr/bin/env python3
"""把 config.yaml / config.share.yaml 中的明文 api_key 消毒为 ${*_API_KEY} 环境变量引用。

覆盖两类位置：
1. ai.channels.<id>.api_key        -> 按通道映射环境变量（CHANNEL_ENV）
2. knowledge.embedding.api_key     -> ${DASHSCOPE_API_KEY}（与主通道同源 dashscope）

规则：
- 已是 ${...} 引用或空串的行跳过（幂等，可重复运行）
- 改动前自动备份 .bak_secretscrub_<HHMMSS>
- 输出只打码，绝不回显密钥本身
"""
import datetime
import re
import shutil
import sys

CHANNEL_ENV = {
    "ark": "ARK_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "moonshot": "MOONSHOT_API_KEY",
    "openai": "OPENAI_API_KEY",
    "qianfan": "QIANFAN_API_KEY",
    "qwen-max": "DASHSCOPE_API_KEY",  # 主通道：用户唯一必设的环境变量（千问/阿里百炼 dashscope 兼容端点）
    "siliconflow": "SILICONFLOW_API_KEY",
    "zhipu": "ZHIPU_API_KEY",
}

CH_RE = re.compile(r"^(    )([A-Za-z0-9_-]+):\s*$")      # 4 空格缩进的通道名
CH_KEY_RE = re.compile(r"^(      api_key:\s*)(\S+)(\s*(?:#.*)?)$")  # 6 空格 api_key（channels 下）
EMB_KEY_RE = re.compile(r"^(    api_key:\s*)(\S+)(\s*(?:#.*)?)$")  # 4 空格 api_key（embedding 下）


def scrub(path: str) -> int:
    lines = open(path, encoding="utf-8").read().splitlines(keepends=True)
    changed = 0
    out = []
    cur_chan = None      # 当前 ai.channels 子通道
    in_embed = False     # 是否位于 knowledge.embedding 段（2 空格父段）
    for ln in lines:
        m = CH_RE.match(ln)
        if m:
            cur_chan = m.group(2)
            out.append(ln)
            continue
        if cur_chan and cur_chan in CHANNEL_ENV:
            km = CH_KEY_RE.match(ln)
            if km and not km.group(2).startswith("${"):
                out.append(km.group(1) + "${" + CHANNEL_ENV[cur_chan] + "}" + km.group(3) + "\n")
                changed += 1
                continue
        # knowledge.embedding 段：以 2 空格 `knowledge:` 开、2 空格 `embedding:` 进入，
        # 遇任何缩进 <=2 的非空/非注释行即结束
        if re.match(r"^  [a-z_]+:\s*$", ln):
            in_embed = ln.startswith("  embedding:")
        elif in_embed and ln.strip() and not ln.startswith(" "):
            in_embed = False
        if in_embed:
            km = EMB_KEY_RE.match(ln)
            if km and not km.group(2).startswith("${"):
                out.append(km.group(1) + "${DASHSCOPE_API_KEY}" + km.group(3) + "\n")
                changed += 1
                continue
        out.append(ln)

    if changed:
        bak = f"{path}.bak_secretscrub_{datetime.datetime.now().strftime('%H%M%S')}"
        shutil.copy2(path, bak)
        open(path, "w", encoding="utf-8").writelines(out)
        print(f"[SCRUB] {path}: {changed} 个明文 api_key → ${{...}} 引用，备份 {bak}")
    else:
        print(f"[SKIP ] {path}: 无明文 api_key 需处理")
    return changed


if __name__ == "__main__":
    total = sum(scrub(p) for p in sys.argv[1:])
    print(f"DONE total={total}")
