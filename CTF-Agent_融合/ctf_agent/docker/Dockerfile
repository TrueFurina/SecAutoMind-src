# =============================================================================
# ctf-tools —— CTF-Agent 的 Linux 工具基线镜像
#
# ✅ 当前状态（2026-11-10 实测，在 172.16.222.99 / Ubuntu 24.04 / docker 29.1.3）
# -----------------------------------------------------------------------------
# **本文件已在本机构建成功并通过 ctf-selftest（21 项全 OK、RC=0）**，镜像 1.64GB。
# 关键步骤实跑结论：
#   · apt 段：binwalk 2.4.3 / nodejs 20.19 / npm / upx-ucl 4.2.4 / python3-pip 全部
#     在 trixie 源里确认存在（`upx` 为 (none)，包名必须是 upx-ucl）；
#   · bkcrack：patch **必须在 /opt/src 里打**（-p1 剥掉头里的 `a/`，路径剩
#     `bkcrack-1.6.1/src/...`）。之前先 `cd bkcrack-1.6.1` 再 -p1 → patch 交互提问
#     "File to patch:" → 非交互下 skip hunk → 编出**无 cross-filter 的假工具**。
#     已加 `-t` 关交互 + 打完后 grep 自检；
#   · rea.mjs：`npm i -g rea-agents` 落在 /usr/local/lib/node_modules/...，
#     正好命中 rea_probe 的探测路径，**无需设 REA_MJS**；
#   · python 依赖走 /opt/venv（debian 13 是 PEP 668 externally-managed）。
#
# 历史记录（保留，说明为什么曾长期不可信）
#   · 2026-10-09：本机（15.8G 物理、可用 1.8G）构建失败——WSL2 VM 被 OOM，
#     apt 下载到一半 `unexpected EOF`。真因是内存，不是配方。
#   · 那之后本机可用的 `ctf-tools:1`（690MB）是 `ziphard-tools:1` 上手编 +
#     `docker commit` 出来的，**无法用本文件复现**。谁删了它就没有了。
#   本文件因此长期只是"离线配方"而非"已验证构建脚本"，上面那行 2026-11-10
#   才把它变成事实。
# =============================================================================
#
# 设计原则（与本项目护栏纪律一致）
# -----------------------------------------------------------------------------
# 1. **可离线复现**：bkcrack 源码 + 适配 patch 全部 (COPY) 进镜像，不在构建时联网
#    拉 GitHub。外部 Registry/网络会漂移，今天的 URL 明天 404，构建就断了。
# 2. **不把二进制产物 COPY 进镜像**：只 COPY 源码 + patch，一律在容器内**现场编译**。
#    手工编出来的 ELF 进不了仓库review，也无法证明它对应哪份源码。
# 3. **构建即自检**：编译完当场跑 `bkcrack --help` / `crackcrc`，build 成功 = 工具真能用。
#    （2026-10-08 的教训：镜像 build 成功但 bkcrack 根本不在里面，白欢喜。）
#
# 用法
# -----------------------------------------------------------------------------
#   docker build -t ctf-tools:1 ctf_agent/docker/
#   docker run --rm ctf-tools:1 ctf-selftest
#   docker run --rm -v "${PWD}:/work" -w /work ctf-tools:1 bash
# =============================================================================

# BASE_IMAGE 可替换：正常网络下默认 debian:13-slim 即可。
# 若所在机器 registry 不可达（例：Docker Desktop 配了 http://127.0.0.1:7890 代理
# 而代理未开 → pull 报 connectex refused），可改用**本地已存在**的镜像救急：
#   docker build --build-arg BASE_IMAGE=python:3.12-slim -t ctf-tools:1 .
# 注意：这只是离线兜底，别把它写成常态——不同 base 的系统库版本会让
# 「在我这儿编得出来」失效。换回默认前先确认 registry 可达。
ARG BASE_IMAGE=debian:13-slim
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

# ── 基础工具集 ───────────────────────────────────────────────────────────────
# 注释里的每一条都对应本项目**实际用过或明确卡过**的能力，不堆无用品。
RUN apt-get update && apt-get install -y --no-install-recommends \
        # 编译 bkcrack / CTF 二进制所需
        build-essential \
        cmake \
        patch \
        pkg-config \
        # ── 坑位记录 ──
        # hard.sh（GCTF'23 crypto-ziphard 官方解）用的是 awk 的 strtonum()，
        # Debian 默认 awk = mawk **不支持 strtonum** → 该步会静默返回空值，
        # 后面 dd 的 skip/offset 全跟着错，且**没有任何报错**。
        # 必须显式装 gawk 并让它成为 awk。
        gawk \
        # MISC/取证常用
        unzip \
        zip \
        p7zip-full \
        file \
        xxd \
        binutils \
        binwalk \
        foremost \
        # ── 坑位记录（2026-10-09 实测逐个查过 trixie 源）──
        # radare2 / rizin / r2 在 Debian 13 trixie 官方源里**一个都没有**
        # （`apt-cache pkgnames | grep -x` 全为 0）。最初写 Dockerfile 时凭印象
        # 塞了 `radare2`，结果 apt-get 返回 100，整个构建炸在一个跟 CTF 无关的
        # 包名上；改猜 `rizin` 照样没有。**教训：包名必须查，不能凭印象。**
        # 需要 r2 时用 radare.org 官方源或源码编，别硬塞不存在的包名。
        # 静态逆向现状由 binutils（objdump/readelf/nm/strings）+ gdb 兜底。
        gdb \
        strace \
        ltrace \
        # 脚本/网络/杂项
        python3 \
        python3-pip \
        python3-venv \
        openssl \
        git \
        curl \
        ca-certificates \
        libbz2-dev \
        zlib1g-dev \
        # ── 2026-11-10 补齐（先查源确认存在，非凭印象）──
        # nodejs 20.19 / npm：rea_probe 的 JS 反编译引擎 rea.mjs 由 npm 包
        #   `rea-agents` 提供，没有 node 这条 lane 整条不可用（实测 test_elf_hint 红）。
        nodejs \
        npm \
        # upx-ucl：UPX 壳题的解包；注意包名是 upx-ucl，`upx` 在 trixie 源里为 (none)
        upx-ucl \
        # p7zip-full 在 trixie 是 transitional 包（16.02），7z 仍可用
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Python 侧依赖（解题脚本会直接 import 这些，_ALLOWED_IMPORTS 里已放行）─────
# 用独立 venv 而不是 --break-system-packages：debian 13 是 PEP 668 externally-managed，
# 直接 pip 装会被拒；venv 还能让镜像内 python 依赖与系统包解耦。
ENV PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir \
           py7zr rarfile capstone httpx scapy \
    && /opt/venv/bin/python -c "import py7zr, rarfile, capstone, httpx, scapy; print('py-deps OK')"
ENV PATH=/opt/venv/bin:${PATH}

# ── rea.mjs（JS 反编译引擎）──────────────────────────────────────────────────
# rea_probe 的探测路径里就有 /usr/local/lib/node_modules/rea-agents/scripts/rea.mjs，
# 用 npm -g 装完后**无需再设 REA_MJS**。装完当场验文件在不在（防「npm 说成功但没落地」）。
ENV NPM_CONFIG_REGISTRY=https://registry.npmmirror.com
RUN npm install -g rea-agents \
    && test -f /usr/local/lib/node_modules/rea-agents/scripts/rea.mjs \
    && node --version

# mawk -> gawk：strtonum 依赖（见上）
RUN update-alternatives --install /usr/bin/awk awk /usr/bin/gawk 50

# ── bkcrack：打了 cross-filter patch 的版本（不是上游原版）────────────────────
# 背景：GCTF'23 crypto-ziphard（Task ㉜）卡的正是它。
#   原版 bkcrack 要求「同一文件内 12 字节连续已知明文」；
#   该题的明文被拆在两个文件（flag.txt 8 字节 + junk.dat 5 字节），
#   需要官方提供的 patch 改成：用 flag.txt 生成候选密钥 → 用 junk.dat 过滤。
# 上游 patch 只到 v1.5.0；这里入库的 `bkcrack-1.6.1-crossfilter.patch` 是把它适配到
#   v1.6.1 的产物（v1.6.1 在 Data.cpp 里新增了 CONTIGUOUS_SIZE / ATTACK_SIZE 守卫，
#   直接沿用 1.5.0 的 patch 会算不出 plaintext 长度）。
COPY vendor/bkcrack-1.6.1.tar.gz            /opt/src/
COPY vendor/bkcrack-1.6.1-crossfilter.patch /opt/src/
COPY vendor/bkcrack-1.5.0.tar.gz            /opt/src/
COPY vendor/bkcrack-1.5.0.patch             /opt/src/
COPY vendor/crackcrc.c                      /opt/src/
COPY vendor/hard.sh                         /opt/src/

WORKDIR /opt/src

RUN set -eux; \
    tar xzf bkcrack-1.6.1.tar.gz; \
    # -p1 剥掉 patch 头里的 a/ ：路径 `a/bkcrack-1.6.1/src/...` → `bkcrack-1.6.1/src/...`，
    # 因此**必须在 /opt/src 里打**，不能先 cd 进 bkcrack-1.6.1（那样 -p1 只剩 src/，
    # 找不到文件 → patch 交互提问 "File to patch:" → 静默 skip → 编出无 cross-filter 的假工具）。
    # -t 关掉交互（2026-11-10 实锤：非交互下它会 skip hunk 并继续往下走）。
    patch -p1 -t --dry-run < bkcrack-1.6.1-crossfilter.patch; \
    patch -p1 -t < bkcrack-1.6.1-crossfilter.patch; \
    # 自检：patch 真的进去了（防止 patch 静默跳过 → 编出假工具）
    grep -q "second-file cross-filter" bkcrack-1.6.1/src/main.cpp; \
    cd bkcrack-1.6.1; \
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release; \
    cmake --build build -j"$(nproc)"; \
    install -m 0755 build/src/bkcrack /usr/local/bin/bkcrack; \
    # ── 构建即自检：二进制真能跑，而不是只存在于 filesystem ──
    bkcrack --version

# crackcrc：按 CRC32 逆推 junk.dat 的 4 字节明文（hard.sh 第 35 行调用）
RUN set -eux; \
    cd /opt/src; \
    gcc -O3 -o crackcrc crackcrc.c; \
    install -m 0755 crackcrc /usr/local/bin/crackcrc

# ── 自检脚本：docker run --rm ctf-tools:1 ctf-selftest ───────────────────────
# 存在的理由：上面每一条都可能在未来某次重建时 silently 失效（依赖没了、
# patch 对不上了、二进制编出来跑不动了）。开关一条命令验全套。
RUN printf '%s\n' \
    '#!/bin/sh' \
    'set -u' \
    'fail=0' \
    'check() { if command -v "$1" >/dev/null 2>&1; then echo "OK   $1"; else echo "MISS $1"; fail=1; fi; }' \
    'for t in bkcrack crackcrc unzip zip 7z objdump readelf gdb strings python3 gawk dd awk cmake g++ node npm upx; do check "$t"; done' \
    'echo "--- python 依赖（解题脚本会直接 import）---"' \
    'python3 -c "import py7zr, rarfile, capstone, httpx, scapy" && echo "OK   py-deps" || { echo "MISS py-deps"; fail=1; }' \
    'echo "--- rea.mjs 必须在探测路径上（否则 rea_probe 整条 lane 不可用）---"' \
    'test -f /usr/local/lib/node_modules/rea-agents/scripts/rea.mjs && echo "OK   rea.mjs" || { echo "MISS rea.mjs"; fail=1; }' \
    'echo "--- bkcrack 必须带 cross-filter（否则 ziphard 跑不出）---"' \
    'strings /usr/local/bin/bkcrack | grep -q "second-file cross-filter" && echo "OK   cross-filter" || { echo "MISS cross-filter"; fail=1; }' \
    'echo "--- awk 必须支持 strtonum（hard.sh 依赖，mawk 不支持）---"' \
    'echo "" | awk "{ print strtonum(42) }" | grep -q 42 && echo "OK   strtonum" || { echo "MISS strtonum"; fail=1; }' \
    'exit $fail' \
    > /usr/local/bin/ctf-selftest && chmod +x /usr/local/bin/ctf-selftest

WORKDIR /work
CMD ["/bin/bash"]
