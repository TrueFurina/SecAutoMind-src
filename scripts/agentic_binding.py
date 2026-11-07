#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§18 agentic 跨层绑定判据（共享模块）。

为什么抽成独立模块：这条判据原本只活在 run_capability_eval.py（外部门禁），
跑批进程（ctf_stepfun_orchestrator.py）自己不带它 ⇒ 结果文件无法自证
「本次跑批的解题子进程被隔离」。抽到共享模块后：
  - run_capability_eval.py 从这里 import（行为逐字不变，历史 verdict 口径不变）；
  - orchestrator 从这里 import self_check_binding()，把绑定结论写进 summary，
    并可用 --require-airgap 在花额度之前 fail-closed（RC=2）。

两侧必须共用同一份实现：判据两份就是两份口径，迟早漂移（F 类失效的温床）。

指纹口径（三处共用，勿单方面改动）：
  fp = sha256(" ".join(command_tokens))，token 之间以**单个空格**连接，
  过滤掉独立的 "--" 分隔符。gen_agentic_isolation_proof.py 生成侧与
  agentic_run_binding() 校验侧都用这个口径。
"""

import hashlib
import os


def agentic_run_binding(proof, command):
    """§18 跨层绑定：机制证据 ≠ 本次跑批的解题子进程被隔离。

    实证（2026-11-06）：`CTF_AIRGAP=1` + 三个开关全开 + 已生成的 IP 直连 proof，
    仍可从 `ctf_stepfun_orchestrator.run_python_tool` 用
    `importlib.import_module('so'+'cket')` 绕过源码正则，IP 直连
    172.16.222.99:22 成功（CONNECTED）。原因是 seccomp 由 Go 二进制自 re-exec 安装，
    而 Python 子进程是 `subprocess.run([python, '-I', '-c', code])`，两者不同层。

    proof 自己已声明这一点：caveats[0]「不证明任何一次跑批真的开了闸」，
    airgap_scope 是 Go 侧 python_session。因此放行需要第二条件：
    `run_binding.command_sha256` == 本次跑批命令指纹，且
    `subprocess_ip_direct_blocked` is True（本次子进程内实跑 A/B）。
    当前证据没有该字段 ⇒ agentic 一律 fail-closed。
    """
    if not isinstance(proof, dict) or proof.get("parse_error"):
        return False, "IP 直连证据缺失或不可解析"
    if proof.get("ip_direct_blocked") is not True or proof.get("af_unix_ok") is not True:
        return False, "机制层 IP 直连 A/B 未成立"
    cmd = [x for x in (command or []) if x != "--"]
    if not cmd:
        return False, ("无跑批命令可绑定；按 proof.caveats，该证据只证明闸门在探测"
                       "二进制上生效，不证明任何一次跑批开了闸")
    bound = proof.get("run_binding")
    if not isinstance(bound, dict):
        return False, ("证据缺 run_binding：作用域是 Go 二进制 seccomp 探测，"
                       "本次跑批解题子进程未独立证明（实测 CTF_AIRGAP=1 下仍可出网）")
    fp = hashlib.sha256(" ".join(cmd).encode("utf-8")).hexdigest()
    if bound.get("command_sha256") != fp:
        return False, "run_binding.command_sha256 与本次跑批命令指纹不符"
    if bound.get("subprocess_ip_direct_blocked") is not True:
        return False, "本次跑批解题子进程无 IP 直连拦截证据"
    return True, "机制证据 + 本次跑批子进程隔离绑定均成立"


def self_check_binding(proof, argv, uid=None):
    """跑批进程的自证：我是不是被 proof 里那条命令启动的进程？

    与 agentic_run_binding() 的区别：外部门禁在**包装层**比对它 `--` 之后的
    token 指纹；跑批进程只能看到自己的 sys.argv，看不到包装层用了哪个解释器
    token，所以不能复算指纹，改用三条更强的等价判据：

    1. 机制层：ip_direct_blocked / af_unix_ok 皆为 True（同 agentic_run_binding）；
    2. UID：proof.uid == 当前进程 uid（proof.caveats[0] 明言只对同 UID 成立；
       Windows 无 getuid，跳过该条并如实标注——隔离证据本来只在服务器产生）；
    3. 命令绑定：proof.run_binding.command 的 token 序列以 sys.argv 为**后缀**
       （包装命令的最后 N 个 token 必须逐字节等于本进程的 argv），
       且 sha256(" ".join(run_binding.command)) == command_sha256
       （防「改了 command 没改指纹」的证据篡改）。

    返回 (ok, why)。任何一条不成立即 False，fail-closed。
    """
    if not isinstance(proof, dict) or proof.get("parse_error"):
        return False, "IP 直连证据缺失或不可解析"
    if proof.get("ip_direct_blocked") is not True or proof.get("af_unix_ok") is not True:
        return False, "机制层 IP 直连 A/B 未成立"
    bound = proof.get("run_binding")
    if not isinstance(bound, dict):
        return False, "证据缺 run_binding：本次跑批解题子进程未独立证明"
    if bound.get("subprocess_ip_direct_blocked") is not True:
        return False, "本次跑批解题子进程无 IP 直连拦截证据"
    # UID：caveats[0] —— 证据只对同 UID 的跑批成立。
    if uid is None:
        uid = os.getuid() if hasattr(os, "getuid") else None
    if uid is not None and proof.get("uid") is not None and proof.get("uid") != uid:
        return False, "proof.uid=%s ≠ 当前 uid=%s（caveats[0]：跨 UID 证据无效）" % (
            proof.get("uid"), uid)
    # 命令绑定：recorded command 以本进程 argv 为后缀。
    recorded = bound.get("command")
    if not isinstance(recorded, list) or not recorded:
        return False, "run_binding.command 缺失或非 token 列表"
    argv = [str(x) for x in (argv or [])]
    if not argv or len(recorded) < len(argv):
        return False, "run_binding.command(%d tokens) 比本进程 argv(%d) 短，无法构成后缀绑定" % (
            len(recorded), len(argv))
    tail = recorded[-len(argv):]
    if tail != argv:
        return False, ("run_binding.command 尾部与本进程 argv 不符（证据属于另一次跑批）: "
                       "recorded_tail=%r argv=%r" % (tail[:8], argv[:8]))
    # 指纹自洽：防「改 command 不改 sha256」的篡改形态。
    fp = hashlib.sha256(" ".join(str(x) for x in recorded).encode("utf-8")).hexdigest()
    if bound.get("command_sha256") != fp:
        return False, "run_binding.command_sha256 与 command token 序列不自洽（证据被篡改）"
    return True, "机制证据 + UID + 命令后缀绑定均成立（本进程即被证明隔离的那次跑批）"


def _selftest():
    """离线真值表：不联网、不产出分数。被 test_ctf_orchestrator_agentic.py 调用。"""
    ok = 0
    total = 0

    def ck(desc, got, want=True, note=""):
        nonlocal ok, total
        total += 1
        good = got is want
        ok += int(good)
        print("  %s %s%s" % ("PASS" if good else "FAIL", desc,
                             "" if good else "  got=%s %s" % (got, note)))

    argv = ["scripts/ctf_stepfun_orchestrator.py", "--provider", "stepfun", "--agentic"]
    wrapper = ["python"] + argv
    fp = hashlib.sha256(" ".join(wrapper).encode("utf-8")).hexdigest()
    good_proof = {
        "ip_direct_blocked": True, "af_unix_ok": True, "uid": 995,
        "run_binding": {"command": wrapper, "command_sha256": fp,
                        "subprocess_ip_direct_blocked": True},
    }

    # agentic_run_binding 原口径（包装层视角）
    ck("绑定：双条件齐备 ⇒ 放行",
       agentic_run_binding(good_proof, wrapper)[0])
    ck("绑定：指纹不符 ⇒ 拒",
       agentic_run_binding({**good_proof,
                            "run_binding": {**good_proof["run_binding"],
                                            "command_sha256": "0" * 64}}, wrapper)[0],
       want=False)
    ck("绑定：缺 run_binding ⇒ 拒",
       agentic_run_binding({k: v for k, v in good_proof.items() if k != "run_binding"},
                           wrapper)[0],
       want=False)

    # self_check_binding（进程自证视角）
    ck("自证：齐备 ⇒ 放行", self_check_binding(good_proof, argv, uid=995)[0])
    ck("自证：UID 不符 ⇒ 拒", self_check_binding(good_proof, argv, uid=1000)[0],
       want=False)
    ck("自证：argv 是另一条命令 ⇒ 拒",
       self_check_binding(good_proof, argv + ["--no-agentic"], uid=995)[0], want=False)
    ck("自证：机制层不成立 ⇒ 拒",
       self_check_binding({**good_proof, "ip_direct_blocked": False}, argv, uid=995)[0],
       want=False)
    ck("自证：子进程未证明拦截 ⇒ 拒",
       self_check_binding({**good_proof,
                           "run_binding": {**good_proof["run_binding"],
                                           "subprocess_ip_direct_blocked": False}},
                          argv, uid=995)[0], want=False)
    # 篡改 command 但不改指纹 ⇒ 指纹不自洽
    tampered = {**good_proof,
                "run_binding": {**good_proof["run_binding"],
                                "command": ["evil"] + argv}}
    ck("自证：改 command 不改指纹 ⇒ 拒（防篡改）",
       self_check_binding(tampered, argv, uid=995)[0], want=False)
    ck("自证：Windows 无 uid（uid=None）⇒ 仍可按其余判据放行",
       self_check_binding(good_proof, argv, uid=None)[0])

    print("agentic_binding selftest %d/%d" % (ok, total))
    return ok == total


if __name__ == "__main__":
    import sys
    sys.exit(0 if _selftest() else 1)
