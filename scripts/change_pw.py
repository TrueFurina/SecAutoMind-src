#!/usr/bin/env python3
"""一次性运维执行器：经 SSH/SFTP 在目标机上按本地配置执行预置步骤。

🔴 2026-11-10 P0 事故重写
本文件前身把 SSH 主机、账号、明文密码、后台登录凭据与待设置的新密码
全部以字面量写进源码，并随 **public** 仓库公开（默认分支与开发分支均可见）。
明文一旦公开即不可撤销：删文件、清 git 历史都救不回来，唯一有效处置是
**轮换对应凭据**。处置顺序见 docs/evidence/凭据泄露处置_20261110.md。

现在本文件不含任何主机、账号、密码、路径、URL、请求体字段名或请求体值：
全部由调用方经一个**本地且不入库**的 JSON 配置提供，路径由环境变量
SAMA_OPS_CONFIG 传入。缺配置 / 缺字段 / 不可解析 ⇒ fail-closed（rc=2），
绝不回退默认值；错误输出只列缺失字段名，不打印任何值。

配置结构（字段名即契约，值一律不入库）：
  {
    "ssh_host": "...", "ssh_user": "...", "ssh_password": "...",
    "ssh_timeout": 15, "cmd_timeout": 15,
    "steps": [
      {"write_path": "...", "payload": {...}, "command": "..."}
    ],
    "cleanup_commands": ["..."]
  }
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

CONFIG_ENV = "SAMA_OPS_CONFIG"
REQUIRED_KEYS = ("ssh_host", "ssh_user", "ssh_password", "steps")
REQUIRED_STEP_KEYS = ("write_path", "payload", "command")


def fail(message: str):
    """只输出字段名与状态，绝不打印配置里的任何值。"""
    print("[FAIL] " + message, file=sys.stderr)
    raise SystemExit(2)


def load_config() -> dict:
    raw = os.environ.get(CONFIG_ENV, "").strip()
    if not raw:
        fail("%s 未设置；本脚本不内嵌任何凭据或运维参数" % CONFIG_ENV)
    path = Path(raw)
    if not path.is_file():
        fail("配置文件不存在或不是普通文件")
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail("配置文件不是合法 JSON（%s）" % type(exc).__name__)
    if not isinstance(cfg, dict):
        fail("配置顶层必须是对象")
    missing = [k for k in REQUIRED_KEYS if not cfg.get(k)]
    if missing:
        fail("配置缺少必需字段：%s" % ", ".join(missing))
    if not isinstance(cfg["steps"], list):
        fail("steps 必须是数组")
    for i, step in enumerate(cfg["steps"], 1):
        if not isinstance(step, dict):
            fail("steps[%d] 必须是对象" % i)
        lack = [k for k in REQUIRED_STEP_KEYS if k not in step]
        if lack:
            fail("steps[%d] 缺少字段：%s" % (i, ", ".join(lack)))
    return cfg


def main() -> int:
    cfg = load_config()
    # 延迟导入：缺配置时先 fail-closed，不因第三方依赖缺失而报出无关堆栈
    import paramiko
    ssh_timeout = int(cfg.get("ssh_timeout", 15))
    cmd_timeout = int(cfg.get("cmd_timeout", 15))
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        cfg["ssh_host"],
        username=cfg["ssh_user"],
        password=cfg["ssh_password"],
        timeout=ssh_timeout,
    )
    try:
        sftp = client.open_sftp()
        try:
            commands = []
            for step in cfg["steps"]:
                with sftp.open(step["write_path"], "w") as fh:
                    fh.write(json.dumps(step["payload"]))
                commands.append(step["command"])
            for cmd in commands + list(cfg.get("cleanup_commands", [])):
                _, stdout, stderr = client.exec_command(cmd, timeout=cmd_timeout)
                stdout.read()
                stderr.read()
                # 只报退出码：stdout/stderr 可能含令牌或凭据，一律不回显
                print("[CMD] exit_status=%s" % stdout.channel.recv_exit_status())
        finally:
            sftp.close()
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
