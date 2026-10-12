#!/usr/bin/env python3
"""在百度云服务器上直接下载并安装 gcc RPM 包（绕过 zypper）"""
import os
import paramiko
import time

# 密码已移出代码：从用户环境变量 BAIDU_SERVER_PASSWORD 读取（2026-09-05 密钥卫生整改）
SERVER_PASSWORD = os.environ.get('BAIDU_SERVER_PASSWORD')
if not SERVER_PASSWORD:
    raise SystemExit('环境变量 BAIDU_SERVER_PASSWORD 未设置，无法连接服务器')

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(os.environ.get('BAIDU_SERVER_HOST', '127.0.0.1'), username='root', password=SERVER_PASSWORD, timeout=15)

def run(cmd, timeout=60):
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if out: print(out)
    if err: print('ERR:', err[:500])
    return out, err

# 1. 从 openSUSE 归档直接下载 gcc 及依赖 RPM
print('=== 1. 下载 gcc RPM 包 ===')
# openSUSE 42.3 归档地址
base = "http://archive.opensuse.org/distribution/leap/42.3/repo/oss/suse/x86_64"
# 先获取目录列表找到确切文件名
run(f'curl -sL "{base}/" | grep -o "gcc[^\"]*\\.rpm" | head -3', timeout=30)

# 直接用已知的包名模式下载
pkgs = [
    "libgcc_s1-7.1.1+r248970-1.4.x86_64.rpm",
    "libgomp1-7.1.1+r248970-1.4.x86_64.rpm",
    "cpp48-4.8.5-24.1.x86_64.rpm",
    "gcc48-4.8.5-24.1.x86_64.rpm",
    "libstdc++48-devel-4.8.5-24.1.x86_64.rpm",
    "libgomp48-devel-4.8.5-24.1.x86_64.rpm",
]

# 但这些版本号不确定，先查目录
print('=== 1b. 查 RPM 目录 ===')
run(f'curl -sL "{base}/" 2>/dev/null | grep -oE "(gcc[0-9]*-[0-9][^\"]*\\.rpm|libgcc_s[^\"]*\\.rpm|libgomp[^\"]*\\.rpm|cpp[0-9]*-[0-9][^\"]*\\.rpm)" | sort -u | head -20', timeout=30)

# 2. 换个更靠谱的方式：用百度云镜像下载
print('=== 2. 百度云镜像下载 ===')
baidubase = "http://mirrors.baidubce.com/opensuse/distribution/leap/42.3/repo/oss/suse/x86_64"
run(f'curl -sL "{baidubase}/" 2>/dev/null | grep -oE "(gcc[^\"]*\\.rpm|libgcc_s[^\"]*\\.rpm|cpp[0-9][^\"]*\\.rpm)" | head -10', timeout=30)

# 3. 如果上面都失败，尝试从阿里镜像下载
print('=== 3. 阿里云镜像 ===')
alibase = "http://mirrors.aliyun.com/opensuse/distribution/leap/42.3/repo/oss/suse/x86_64"
run(f'curl -sL "{alibase}/" 2>/dev/null | grep -oE "(gcc[^\"]*\\.rpm|libgcc_s[^\"]*\\.rpm|cpp[0-9][^\"]*\\.rpm)" | head -10', timeout=30)

# 4. 最后手段：从 GitHub release 下载预编译的静态 gcc
print('=== 4. 尝试直接安装 gcc 源码编译 ===')
run('which cc 2>/dev/null || which tcc 2>/dev/null || echo "无任何C编译器"')

client.close()
print('=== 诊断完成 ===')
