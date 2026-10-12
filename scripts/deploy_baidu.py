#!/usr/bin/env python3
import os
import paramiko
import time

# 密码已移出代码：从用户环境变量 BAIDU_SERVER_PASSWORD 读取（2026-09-05 密钥卫生整改）
SERVER_PASSWORD = os.environ.get('BAIDU_SERVER_PASSWORD')
if not SERVER_PASSWORD:
    raise SystemExit('环境变量 BAIDU_SERVER_PASSWORD 未设置，无法连接服务器')

def connect():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(os.environ.get('BAIDU_SERVER_HOST', '127.0.0.1'), username='root', password=SERVER_PASSWORD, timeout=15)
    return client

def run(client, cmd, timeout=30):
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if out: print(out)
    if err and 'warning' not in err.lower(): print('ERR:', err[:300])
    return out, err

# Step1: 修复bashrc + 创建目录
print('=== Step1: 环境准备 ===')
c = connect()
run(c, 'printf \'# .bashrc\\nexport PATH=/usr/local/go/bin:$PATH\\n\' > /root/.bashrc')
run(c, 'mkdir -p /opt/secautomind/data')
sftp = c.open_sftp()
sftp.close()
c.close()
print('Step1 done')

# Step2: 下载二进制（用nohup后台执行，避免超时断连）
print('=== Step2: 下载二进制 ===')
c = connect()
run(c, 'ls -lh /opt/secautomind/secautomind-ai 2>/dev/null', timeout=10)
out, _ = run(c, 'test -f /opt/secautomind/secautomind-ai && echo exists || echo missing', timeout=10)
if 'exists' in str(out):
    print('二进制已存在，跳过下载')
else:
    print('开始后台下载...')
    run(c, 'nohup bash -c \'curl -sL "https://github.com/TrueFurina/SecAutoMind-src/releases/download/v1.7.25/secautomind-ai-linux-amd64" -o /opt/secautomind/secautomind-ai && chmod +x /opt/secautomind/secautomind-ai && echo download_done > /tmp/dl_status\' > /tmp/dl.log 2>&1 &', timeout=10)
    print('下载已在后台启动，等待...')
    # 轮询等待
    for i in range(60):
        time.sleep(5)
        c2 = connect()
        out2, _ = run(c2, 'cat /tmp/dl_status 2>/dev/null', timeout=10)
        c2.close()
        if 'download_done' in str(out2):
            print(f'下载完成（耗时约{i*5}秒）')
            break
        print(f'  等待中... {i*5}s')
    else:
        print('下载超时（300s），检查日志')
        c2 = connect()
        run(c2, 'tail -5 /tmp/dl.log 2>/dev/null', timeout=10)
        c2.close()
c.close()

# Step3: 下载web资源（同样后台执行）
print('=== Step3: 下载web资源 ===')
c = connect()
out, _ = run(c, 'test -d /opt/secautomind/web/static && echo exists || echo missing', timeout=10)
if 'exists' in str(out):
    print('web资源已存在，跳过')
else:
    print('开始后台下载web资源...')
    run(c, 'nohup bash -c \'cd /opt/secautomind && curl -sL "https://github.com/TrueFurina/SecAutoMind-src/archive/refs/tags/v1.7.25.tar.gz" -o src.tar.gz && tar xzf src.tar.gz --strip-components=1 SecAutoMind-src-1.7.25/web && rm src.tar.gz && echo web_done > /tmp/web_status\' > /tmp/web_dl.log 2>&1 &', timeout=10)
    for i in range(30):
        time.sleep(5)
        c2 = connect()
        out2, _ = run(c2, 'cat /tmp/web_status 2>/dev/null', timeout=10)
        c2.close()
        if 'web_done' in str(out2):
            print(f'web资源下载完成')
            break
        print(f'  等待中... {i*5}s')
c.close()

# Step4: 生成配置 + systemd服务（用SFTP上传）
print('=== Step4: 配置文件 + 服务 ===')
c = connect()
sftp = c.open_sftp()

config = """# SecAutoMind - Baidu Cloud Deploy
version: "v1.7.25"
server:
  host: 0.0.0.0
  port: 18086
  tls_enabled: false
agent:
  default_channel: deepseek
  max_iterations: 50
knowledge:
  enabled: true
  db_path: data/knowledge.db
rbac:
  enabled: true
hitl:
  enabled: true
  default_mode: audit
log:
  level: info
  file: data/secautomind.log
"""
with sftp.open('/opt/secautomind/config.yaml', 'w') as f:
    f.write(config)
print('config.yaml 已上传')

service = """[Unit]
Description=SecAutoMind AI Platform
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/secautomind
ExecStart=/opt/secautomind/secautomind-ai
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
with sftp.open('/etc/systemd/system/secautomind.service', 'w') as f:
    f.write(service)
print('systemd service 已上传')

sftp.close()
run(c, 'systemctl daemon-reload && systemctl enable secautomind && echo enabled')
c.close()

# Step5: 启动服务
print('=== Step5: 启动服务 ===')
c = connect()
run(c, 'systemctl stop secautomind 2>/dev/null; sleep 1')
run(c, 'systemctl start secautomind')
time.sleep(5)
run(c, 'systemctl status secautomind --no-pager | head -10')
run(c, 'ss -tlnp | grep 18086')
run(c, 'cat /opt/secautomind/data/admin_initial_password.txt 2>/dev/null || echo "密码文件待生成"')
c.close()

print('=== 全部完成 ===')
