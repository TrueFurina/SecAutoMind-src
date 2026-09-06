#!/usr/bin/env python3
import paramiko, json

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('120.48.36.201', username='root', password='Zmj060220', timeout=15)
sftp = client.open_sftp()

def run(cmd, timeout=15):
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode().strip(), stderr.read().decode().strip()

# 1. 登录
login_body = json.dumps({"username": "admin", "password": "Xo8yCyNsHSa8-hbQAEd9JisM"})
with sftp.open('/tmp/login.json', 'w') as f:
    f.write(login_body)
out, _ = run('curl -s -X POST http://127.0.0.1:18086/api/auth/login -H "Content-Type: application/json" -d @/tmp/login.json')
resp = json.loads(out)
token = resp.get('token', '')
print(f"登录: {'成功' if token else '失败'}")

# 2. 改密码（camelCase 字段名！）
chpw_body = json.dumps({"oldPassword": "Xo8yCyNsHSa8-hbQAEd9JisM", "newPassword": "SecAuto@Mind2026"})
with sftp.open('/tmp/chpw.json', 'w') as f:
    f.write(chpw_body)
out, _ = run(f'curl -s -X POST http://127.0.0.1:18086/api/auth/change-password -H "Content-Type: application/json" -H "Authorization: Bearer {token}" -d @/tmp/chpw.json')
print(f"改密码: {out}")

# 3. 验证新密码
login_new = json.dumps({"username": "admin", "password": "SecAuto@Mind2026"})
with sftp.open('/tmp/login_new.json', 'w') as f:
    f.write(login_new)
out, _ = run('curl -s -X POST http://127.0.0.1:18086/api/auth/login -H "Content-Type: application/json" -d @/tmp/login_new.json')
resp = json.loads(out) if out else {}
print(f"新密码登录: {'成功' if resp.get('token') else '失败 - ' + resp.get('error', '')}")

# 清理
for f in ['/tmp/login.json', '/tmp/chpw.json', '/tmp/login_new.json']:
    run(f'rm -f {f}')
sftp.close()
client.close()
