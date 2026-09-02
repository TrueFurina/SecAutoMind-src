#!/bin/bash
set -euo pipefail

# SecAutoMind 腾讯轻量云一键部署脚本
# 适用系统：Ubuntu 22.04 LTS / TencentOS Server 3.1
# 运行方式：以 root 身份执行
#   ./deploy_tencent_lighthouse.sh your-domain.com
# 无域名时：
#   ./deploy_tencent_lighthouse.sh

PROJECT_DIR="/opt/secautomind"
DOMAIN="${1:-}"
GO_VERSION="1.25.0"
GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
SERVICE_NAME="secautomind"

# 颜色输出
info() { echo -e "\033[0;34m[INFO]\033[0m $1"; }
ok() { echo -e "\033[0;32m[OK]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
err() { echo -e "\033[0;31m[ERROR]\033[0m $1"; }

# 0. 检查 root
if [[ $EUID -ne 0 ]]; then
  err "请使用 root 权限运行本脚本（sudo -i）"
  exit 1
fi

info "开始部署 SecAutoMind 到腾讯轻量云 ..."
info "项目目录: $PROJECT_DIR"
[[ -n "$DOMAIN" ]] && info "域名: $DOMAIN" || warn "未提供域名，将仅通过 HTTP 8080 + 127.0.0.1 提供服务"

# 1. 安装系统依赖
info "安装系统依赖 ..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  curl wget git ca-certificates \
  build-essential gcc \
  python3 python3-venv python3-pip python3-dev python-is-python3 \
  nginx cron

# 2. 安装 Go 1.25+
if ! command -v go >/dev/null 2>&1 || [[ $(go version | awk '{print $3}' | sed 's/go//') < "$GO_VERSION" ]]; then
  info "安装 Go $GO_VERSION ..."
  cd /tmp
  rm -f "$GO_TARBALL"
  wget -q "https://go.dev/dl/$GO_TARBALL"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$GO_TARBALL"
  rm -f "$GO_TARBALL"
  if ! grep -q '/usr/local/go/bin' /etc/profile.d/go.sh 2>/dev/null; then
    echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
  fi
  export PATH=$PATH:/usr/local/go/bin
fi
ok "Go 版本: $(go version)"

# 3. 准备项目目录
if [[ ! -d "$PROJECT_DIR" ]]; then
  err "未找到项目目录 $PROJECT_DIR，请先把项目上传到 /opt/secautomind 后再运行本脚本"
  exit 1
fi

cd "$PROJECT_DIR"

# 4. 配置 Go 国内代理
export GOPROXY=https://goproxy.cn,direct
info "GOPROXY: $GOPROXY"

# 5. 创建 Python venv 并安装依赖
if [[ ! -d "venv" ]]; then
  info "创建 Python venv ..."
  python3 -m venv venv
fi
info "安装 Python 依赖 ..."
source venv/bin/activate
pip install --upgrade pip
if [[ -f requirements.txt ]]; then
  # angr 可能因缺少 Rust 失败，允许继续
  pip install -r requirements.txt || warn "部分 Python 依赖安装失败（常见为 angr 需要 Rust），将继续部署"
fi

# 6. 下载 Go 依赖并编译
info "下载 Go 依赖 ..."
go mod download

info "编译 SecAutoMind ..."
go build -o secautomind-ai cmd/server/main.go
ok "编译完成: $(ls -lh secautomind-ai | awk '{print $9, $5}')"

# 7. 修改 config.yaml 监听地址为 127.0.0.1（避免直接暴露）
if [[ -f config.yaml ]]; then
  info "调整 config.yaml 监听地址为 127.0.0.1 ..."
  sed -i -E 's/^[[:space:]]*host:[[:space:]]*0\.0\.0\.0[[:space:]]*$/  host: 127.0.0.1/' config.yaml
  # 如果 sed 未匹配到（缩进不同），给出提示
  if grep -qE '^[[:space:]]*host:[[:space:]]*0\.0\.0\.0' config.yaml; then
    warn "config.yaml 的 host 仍为 0.0.0.0，请手动改为 127.0.0.1"
  fi
else
  warn "未找到 config.yaml，请基于 config.example.yaml 创建"
fi

# 8. 创建 systemd 服务
cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=SecAutoMind Multi-Agent Security Platform
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR
Environment="PATH=$PROJECT_DIR/venv/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$PROJECT_DIR/secautomind-ai -config $PROJECT_DIR/config.yaml --http
ExecStop=/bin/kill -SIGTERM \$MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ${SERVICE_NAME}

# 9. 启动服务（先停止旧进程）
info "启动 SecAutoMind 服务 ..."
systemctl stop ${SERVICE_NAME} 2>/dev/null || true
systemctl start ${SERVICE_NAME}
sleep 3
if systemctl is-active --quiet ${SERVICE_NAME}; then
  ok "服务已启动"
else
  err "服务启动失败，查看日志：journalctl -u ${SERVICE_NAME} -n 50"
  exit 1
fi

# 10. 配置 nginx
NGINX_CONF="/etc/nginx/sites-available/secautomind"
rm -f "$NGINX_CONF"

if [[ -n "$DOMAIN" ]]; then
  info "配置 nginx + HTTPS（域名: $DOMAIN） ..."
  cat > "$NGINX_CONF" <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
    }
}
EOF

  # 申请 Let's Encrypt 证书
  if ! command -v certbot >/dev/null 2>&1; then
    apt-get install -y certbot python3-certbot-nginx
  fi
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "admin@${DOMAIN}" || warn "SSL 证书申请失败，请检查域名解析是否已生效"
else
  info "配置 nginx 本地代理（HTTP） ..."
  cat > "$NGINX_CONF" <<EOF
server {
    listen 80 default_server;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
    }
}
EOF
fi

# 启用站点
ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/secautomind
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
nginx -t && systemctl reload nginx
ok "nginx 配置完成"

# 11. 安全提示
info "部署完成"
ok "SecAutoMind 已运行在 http://127.0.0.1:8080"
if [[ -n "$DOMAIN" ]]; then
  ok "公网访问地址: https://$DOMAIN"
else
  ok "公网访问地址: http://YOUR_PUBLIC_IP （需安全组放行 80）"
fi
warn "请确保安全组未放行 8080，只开放 22/80/443"
warn "请编辑 config.yaml 填写真实的 AI API Key，并运行 './secautomind-ai --reset-admin-password' 重置 admin 密码"
warn "终审前请将 base_url 切换为安恒 AI 安全网关地址"
