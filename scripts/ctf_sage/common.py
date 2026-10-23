"""CTF 密码攻击模板库 —— 公共层（LLL / IO 契约 / 前提检查纪律）。

设计纪律（源自 2025-2026 实证调研，见 docs/zh-CN/competition-2026/求解能力深化计划_20261023.md）：
  1. 模型提议、求解器处置、失败反馈——本库是"求解器"，LLM 只负责填参数。
  2. 参数不满足攻击前提时，必须返回 not_applicable 并说明原因（AICrypto 实证头号失败模式：
     套攻击模式不检查前提）。禁止瞎跑返回垃圾。
  3. 一切"解出"以候选 flag 明文输出为准；调用方须自行过 flag 校验（sha256/形态）。
  4. 纯 Python3 + sympy 自包含（Fraction 精确算术 LLL）；Sage 仅作可选加速，软探测。
  5. 禁网；每个模板可独立 --selftest（合成参数造题→解题→断言）。

IO 契约（所有模板一致）：
  输入：JSON（stdin 或 --params 文件），字段见各模板 docstring。
  输出：JSON（stdout）：
    {"status": "solved" | "not_applicable" | "error",
     "flags": ["<候选 flag 明文>", ...],
     "detail": "人类可读说明",
     "engine": "<模板名>"}
  status 语义：
    solved        = 攻击成功，flags 非空（调用方仍需校验 flag 真伪）
    not_applicable= 前提不满足（附原因），不产出垃圾
    error         = 输入非法/内部错误（附原因）
"""

from __future__ import annotations

import json
import sys
from fractions import Fraction


# ---------------------------------------------------------------- IO 契约

def emit(status: str, flags=None, detail: str = "", engine: str = "") -> None:
    """按统一契约输出 JSON 到 stdout。"""
    json.dump(
        {
            "status": status,
            "flags": flags or [],
            "detail": detail,
            "engine": engine,
        },
        sys.stdout,
        ensure_ascii=False,
    )
    sys.stdout.write("\n")


def read_params(argv: list[str]) -> dict:
    """从 --params <file> 或 stdin 读 JSON 参数。"""
    args = list(argv)
    if "--params" in args:
        path = args[args.index("--params") + 1]
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    raw = sys.stdin.read().strip()
    if not raw:
        raise ValueError("空输入：需要 JSON 参数（stdin 或 --params <file>）")
    return json.loads(raw)


def need(params: dict, *keys: str) -> None:
    """必填参数校验；缺失即 error（fail-closed，不许默认值蒙混）。"""
    missing = [k for k in keys if k not in params or params[k] is None]
    if missing:
        raise ValueError(f"缺少必填参数: {', '.join(missing)}")


def as_int(value, name: str) -> int:
    """参数转 int；接受 int / 十进制字符串 / 0x 前缀。"""
    if isinstance(value, bool):
        raise ValueError(f"{name}: 非法整数（bool）")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        try:
            return int(s, 0) if s.lower().startswith(("0x", "0b", "0o")) else int(s, 10)
        except ValueError as exc:
            raise ValueError(f"{name}: 非法整数 '{value}'") from exc
    raise ValueError(f"{name}: 需要整数，得到 {type(value).__name__}")


def flag_candidates(text: str, prefix: str = "") -> list[str]:
    """从文本提取 flag 形态候选（品牌前缀+花括号；或指定 prefix）。"""
    import re

    pats = [
        r"[A-Za-z0-9_]*(?:flag|ctf|key|dasctf)\s*[=:：]?\s*\{[^}]{4,}\}",
        r"\b[A-Z][A-Z0-9]{2,15}\{[^}]{4,}\}",
    ]
    seen: set[str] = set()
    out: list[str] = []
    for pat in pats:
        for m in re.findall(pat, text):
            if m not in seen:
                seen.add(m)
                out.append(m)
    return out


# ---------------------------------------------------------------- LLL（精确算术）

def _dot(a: list[Fraction], b: list[Fraction]) -> Fraction:
    return sum(x * y for x, y in zip(a, b))


def _gram_schmidt(B: list[list[Fraction]]) -> tuple[list[list[Fraction]], list[list[Fraction]]]:
    n = len(B)
    Bstar: list[list[Fraction]] = []
    mu = [[Fraction(0)] * n for _ in range(n)]
    for i in range(n):
        bi = list(B[i])
        for j in range(i):
            denom = _dot(Bstar[j], Bstar[j])
            if denom != 0:
                mu[i][j] = _dot(B[i], Bstar[j]) / denom
                bi = [bi[k] - mu[i][j] * Bstar[j][k] for k in range(len(bi))]
        Bstar.append(bi)
    return Bstar, mu


def lll_reduce(basis: list[list[int | Fraction]], delta: Fraction = Fraction(3, 4)) -> list[list[Fraction]]:
    """LLL 格基规约（Fraction 精确算术，无浮点误差）。

    输入：整数基向量列表。输出：规约后的基。
    实现：增量 mu 更新——RED(k,l) 只改 O(l) 个 mu（Bstar/d 不变，推导：
      B[k] = Σ_i c_{k,i}·Bstar[i] 且 mu[k][i]=c_{k,i}；B[k]-q·B[l] 使
      c_{k,i} -= q·c_{l,i} (i≤l)，即 mu[k][i] -= q·mu[l][i] (i<l)、mu[k][l] -= q），
      仅 swap 时全量重算 GS。规模：dim<=~40、条目<=~256bit（ Fraction 兜底路径）；
    大维度/大条目优先 sage（`sage -c`）或 fpylll——由调用方软探测。
    """
    B = [[Fraction(x) for x in v] for v in basis]
    n = len(B)
    if n == 0:
        return B
    width = len(B[0])

    Bstar, mu = _gram_schmidt(B)
    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = round(mu[k][j])  # Fraction -> int（银行家舍入，LLL 可接受）
                if q != 0:
                    B[k] = [B[k][i] - q * B[j][i] for i in range(width)]
                    for i in range(j):
                        mu[k][i] -= q * mu[j][i]
                    mu[k][j] -= q
        lhs = _dot(Bstar[k], Bstar[k])
        rhs = (delta - mu[k][k - 1] ** 2) * _dot(Bstar[k - 1], Bstar[k - 1])
        if lhs >= rhs:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            Bstar, mu = _gram_schmidt(B)
            k = max(k - 1, 1)
    return B


def lll_reduce_naive(basis: list[list[int | Fraction]], delta: Fraction = Fraction(3, 4)) -> list[list[Fraction]]:
    """LLL 参考实现（每次 RED/swap 全量重算 GS）——慢，但用作 lll_reduce 的交叉验证基准。"""
    B = [[Fraction(x) for x in v] for v in basis]
    n = len(B)
    if n == 0:
        return B
    width = len(B[0])

    def regso() -> tuple[list[list[Fraction]], list[list[Fraction]]]:
        return _gram_schmidt(B)

    Bstar, mu = regso()
    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = round(mu[k][j])
                if q != 0:
                    B[k] = [B[k][i] - q * B[j][i] for i in range(width)]
                    Bstar, mu = regso()
        lhs = _dot(Bstar[k], Bstar[k])
        rhs = (delta - mu[k][k - 1] ** 2) * _dot(Bstar[k - 1], Bstar[k - 1])
        if lhs >= rhs:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            Bstar, mu = regso()
            k = max(k - 1, 1)
    return B


def is_lll_reduced(B: list[list[Fraction]], delta: Fraction = Fraction(3, 4)) -> bool:
    """校验 B 满足 LLL 规约条件（|mu|<=1/2 且 Lovász 条件）——供自测断言输出质量。"""
    n = len(B)
    if n == 0:
        return True
    Bstar, mu = _gram_schmidt(B)
    for i in range(n):
        for j in range(i):
            if abs(mu[i][j]) > Fraction(1, 2):
                return False
        if i > 0:
            lhs = _dot(Bstar[i], Bstar[i])
            rhs = (delta - mu[i][i - 1] ** 2) * _dot(Bstar[i - 1], Bstar[i - 1])
            if lhs < rhs:
                return False
    return True


def short_vectors(basis: list[list[int | Fraction]], top: int = 1) -> list[list[Fraction]]:
    """LLL 后按范数排序返回最短的 top 个向量。"""
    red = lll_reduce(basis)
    red.sort(key=lambda v: _dot(v, v))
    return red[:top]


def has_sage() -> bool:
    """软探测 SageMath（可选加速路径）。"""
    import shutil

    return shutil.which("sage") is not None


def integer_nth_root(n: int, k: int) -> int:
    """精确整数 k 次根（floor）。"""
    if n < 0:
        raise ValueError("negative radicand")
    if n == 0:
        return 0
    lo, hi = 0, 1 << ((n.bit_length() + k - 1) // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo
