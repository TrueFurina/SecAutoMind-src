package projectprompt

// CTFGovernanceSection 返回 CTF 场景代码执行治理段（P0-1，2026-10-25 落地）。
//
// 依据 docs/zh-CN/competition-2026/求解能力深化计划_20261023.md P0-1：
// 纲领「模型提议、求解器处置、失败反馈进下一轮」——LLM 从不亲自做需要确定性的步骤。
// 失败模式实证（AICrypto 2507.09580：LLM 单独 lattice 子类仅 8.3–25%；
// KryptoPilot 2601.09129：治理化调用 Sage 是正解）：
//   - 套攻击模式不检查前提 = 两路调研共同头号失败模式；
//   - 重造轮子（自己推 LLL/Coppersmith）= 可避免的确定性浪费。
//
// 本段挂在有代码执行面的系统提示后（单代理 / L3 fallback），与
// ShellExecExecuteGuidanceSection 互补：那段管 exec/execute 分工，本段管 CTF 解题纪律。
func CTFGovernanceSection() string {
	return `CTF 解题治理（代码执行场景，优先级高于通用效率技巧）：

【模板优先——禁止从零推数学】
crypto 数学题（格/Coppersmith/HNP/Boneh-Durfee/DLP/Håstad/截断 LFSR）必须先查
scripts/ctf_sage/ 密码攻击模板库（仓库根相对路径），用 execute 跑，禁止自己推公式或重写格攻击：
- t1_coppersmith.py    多项式 mod N 小根（Coppersmith；RSA 已知高位/低指数场景）
- t2_ecdsa_hnp.py      ECDSA nonce 复用 / HNP 格恢复私钥（签名数量与 nonce 熵要够）
- t3_truncated_lfsr.py LFSR 全输出 Berlekamp-Massey / 截断高位已知恢复
- t4_boneh_durfee.py   RSA 私指数 d < N^0.292（Herrmann-May 构造）
- t5_dlp_bsgs_ph.py    离散对数 BSGS + Pohlig-Hellman（光滑阶）
- t6_hastad_broadcast.py 同明文低指数广播（接收者组数 ≥ e）
IO 契约：stdin 一个 JSON → stdout 一个 JSON {status, flags, detail}。
status=not_applicable 表示前提不满足——这是模板的正常回答，据此换攻击路，不许硬套。

【前提检查（头号失败模式）】
套模板前先核对前提：签名数量/nonce 熵、d 的理论上界、广播组数、LFSR 输出条数。
前提不满足时要么补数据（如下载更多附件），要么明确换路；不许把"跑了个模板"当进展。

【禁网】
沙箱内禁止访问外网（防联网抄 flag/查答案）。只允许题目给定的目标地址与平台接口。

【flag 验证】
每个解题脚本必须 print 候选 flag 并过形态校验（flag{...} 或平台指定格式）后才算候选；
禁止把中间量（私钥/格根/明文/哈希）当 flag 提交。

【依赖降级（软探测，fail-closed）】
python3 必备；sage/pwntools/gmpy2/numpy 软探测——缺失时用纯 Python 路径：
模板库六个模板全部纯 Python 自包含（无 numpy 时自动退化为暴力/精确验证），
不许崩、不许把"缺依赖"谎报成"无解"。探测清单见 scripts/ctf_sage/probe_env.py。

【长脚本落盘】
长脚本/请求体/Payload 必须先用 write_file 写入会话工作目录，再用 execute 执行短命令；
禁止把长内容内联进 command 行。`
}
