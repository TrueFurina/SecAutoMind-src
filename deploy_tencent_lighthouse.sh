#!/bin/bash
set -euo pipefail

# SecAutoMind 腾讯轻量云一键部署脚本
# 适用系统：Ubuntu 20.04+/Debian（apt）· TencentOS Server 3.x / CentOS Stream 8+ / Rocky（dnf|yum）
# 运行方式：以 root 身份执行
#   ./deploy_tencent_lighthouse.sh your-domain.com   # 有域名：自动申请 Let's Encrypt 证书
#   ./deploy_tencent_lighthouse.sh                   # 无域名：仅 HTTP 80 反向代理 + 本机验证
#
# 设计要点（与仓库实现对齐，勿凭印象改）：
#   1) 端口**不写死**，从 config.yaml 的 server.port 读取（本仓库为 18086；config.example.yaml 为 8080）。
#   2) 密钥**不落盘**：config.yaml 用 ${ENV} 占位（DASHSCOPE_API_KEY 等），由 systemd EnvironmentFile 注入。
#   3) 服务以 --http 启动（config.yaml 默认 tls_enabled: true + 自签证书），TLS 统一交给 nginx 终结。
#   4) SQLite 已迁纯 Go（glebarez），CGO_ENABLED=0 构建，**无需 gcc**。
#   5) 构建产物与仓库权威配方一致：`CGO_ENABLED=0 go build -trimpath -ldflags "-w -s" ./cmd/server`。

PROJECT_DIR="/opt/secautomind"
DOMAIN="${1:-}"
GO_VERSION="1.25.0"
GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
SERVICE_NAME="secautomind"
ENV_FILE="/etc/secautomind.env"
FALLBACK_PORT="18086"   # 仅在 config.yaml 读不到 server.port 时兜底

info() { echo -e "\033[0;34m[INFO]\033[0m $1"; }
ok()   { echo -e "\033[0;32m[OK]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
err()  { echo -e "\033[0;31m[ERROR]\033[0m $1"; }

# 0. 检查 root
if [[ $EUID -ne 0 ]]; then
  err "请使用 root 权限运行本脚本（sudo -i）"
  exit 1
fi

# ── 包管理器探测（Ubuntu/Debian 用 apt，TencentOS/CentOS/Rocky 用 dnf|yum）──
PKG=""
if   command -v apt-get >/dev/null 2>&1; then PKG="apt"
elif command -v dnf     >/dev/null 2>&1; then PKG="dnf"
elif command -v yum     >/dev/null 2>&1; then PKG="yum"
else
  err "未识别的发行版：找不到 apt-get / dnf / yum。请改用 Ubuntu 22.04 镜像后重试。"
  exit 1
fi

# nginx 站点配置目录：Debian 系走 sites-available/sites-enabled，RHEL 系走 conf.d
if [[ "$PKG" == "apt" ]]; then
  NGINX_SITE="/etc/nginx/sites-available/secautomind"
  NGINX_LINK="/etc/nginx/sites-enabled/secautomind"
else
  NGINX_SITE="/etc/nginx/conf.d/secautomind.conf"
  NGINX_LINK=""
fi

pkg_refresh() {
  case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get update -y ;;
    dnf) dnf makecache -y ;;
    yum) yum makecache -y ;;
  esac
}

pkg_install() {
  case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" ;;
    dnf) dnf install -y "$@" ;;
    yum) yum install -y "$@" ;;
  esac
}

info "开始部署 SecAutoMind 到腾讯轻量云 ..."
info "包管理器: $PKG | 项目目录: $PROJECT_DIR"
if [[ -n "$DOMAIN" ]]; then info "域名: $DOMAIN"; else warn "未提供域名：将仅通过 HTTP 80 反向代理提供服务（无 HTTPS）"; fi

# 1. 安装系统依赖（不含 gcc/build-essential —— 项目免 cgo）
info "安装系统依赖 ..."
pkg_refresh
if [[ "$PKG" == "apt" ]]; then
  pkg_install curl wget git ca-certificates python3 python3-venv python3-pip python3-dev nginx cron
else
  pkg_install curl wget git ca-certificates python3 python3-pip python3-devel nginx cronie
fi

# 2. 安装 Go 1.25+（按主次版本号数值比较，避免字符串比较踩 "1.9 > 1.25" 的坑）
need_go=1
if command -v go >/dev/null 2>&1; then
  cur="$(go version | awk '{print $3}' | sed 's/^go//')"
  cur_major="${cur%%.*}"; cur_rest="${cur#*.}"; cur_minor="${cur_rest%%.*}"
  want_major="${GO_VERSION%%.*}"; want_rest="${GO_VERSION#*.}"; want_minor="${want_rest%%.*}"
  if (( cur_major > want_major )) || { (( cur_major == want_major )) && (( cur_minor >= want_minor )); }; then
    need_go=0
  fi
fi
if (( need_go == 1 )); then
  info "安装 Go $GO_VERSION ..."
  cd /tmp
  rm -f "$GO_TARBALL"
  wget -q "https://golang.google.cn/dl/$GO_TARBALL"   # 官方中国站；海外机器可换回 https://go.dev/dl/
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$GO_TARBALL"
  rm -f "$GO_TARBALL"
  echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
  chmod 0644 /etc/profile.d/go.sh
fi
export PATH="$PATH:/usr/local/go/bin"
command -v go >/dev/null 2>&1 || { err "Go 安装失败，请检查网络或手动安装 Go ≥ 1.25"; exit 1; }
ok "Go 版本: $(go version)"

# 3. 项目目录
if [[ ! -d "$PROJECT_DIR" ]]; then
  err "未找到项目目录 $PROJECT_DIR，请先把项目上传到 /opt/secautomind 后再运行本脚本"
  exit 1
fi
cd "$PROJECT_DIR"

# 4. 确保存在 config.yaml
if [[ ! -f config.yaml ]]; then
  if [[ -f config.example.yaml ]]; then
    warn "未找到 config.yaml，已从 config.example.yaml 复制一份（需再注入 API Key）"
    cp config.example.yaml config.yaml
  else
    err "既无 config.yaml 也无 config.example.yaml，无法继续"
    exit 1
  fi
fi

# 4.1 从 config.yaml 的 server 段读取 host/port（端口不写死）
cfg_get_server() {
  awk -v k="$1" '
    /^server:[[:space:]]*$/ { inblk = 1; next }
    /^[^[:space:]#]/ { inblk = 0 }
    inblk {
      line = $0
      sub(/[[:space:]]*#.*/, "", line)
      if (line ~ "^[[:space:]]*" k "[[:space:]]*:") {
        sub("^[[:space:]]*" k "[[:space:]]*:[[:space:]]*", "", line)
        gsub(/"/, "", line); gsub(/\047/, "", line); gsub(/[[:space:]]/, "", line)
        print line
        exit
      }
    }
  ' "$2"
}
APP_PORT="$(cfg_get_server port config.yaml || true)"
APP_HOST="$(cfg_get_server host config.yaml || true)"
[[ "$APP_PORT" =~ ^[0-9]+$ ]] || { warn "无法从 config.yaml 读取 server.port，使用兜底端口 $FALLBACK_PORT"; APP_PORT="$FALLBACK_PORT"; }
info "config.yaml 监听: ${APP_HOST:-?}:$APP_PORT"

# 4.2 强制只听本机（公网入口交给 nginx）
if [[ "$APP_HOST" != "127.0.0.1" ]]; then
  info "将 config.yaml 的 server.host 收紧为 127.0.0.1（公网访问走 nginx） ..."
  awk '
    /^server:[[:space:]]*$/ { inblk = 1; print; next }
    /^[^[:space:]#]/ { inblk = 0 }
    inblk && /^[[:space:]]*host[[:space:]]*:/ {
      cmt = ""
      if (match($0, /#.*/)) cmt = " " substr($0, RSTART)
      print "  host: 127.0.0.1" cmt
      next
    }
    { print }
  ' config.yaml > config.yaml.tmp && mv config.yaml.tmp config.yaml
  now_host="$(cfg_get_server host config.yaml || true)"
  if [[ "$now_host" != "127.0.0.1" ]]; then
    warn "config.yaml 的 server.host 仍为 '$now_host'，请手动改为 127.0.0.1"
  fi
fi

# 5. Python venv + 依赖
export GOPROXY=https://goproxy.cn,direct
info "GOPROXY: $GOPROXY"
if [[ ! -d venv ]]; then
  info "创建 Python venv ..."
  python3 -m venv venv
fi
info "安装 Python 依赖 ..."
# shellcheck disable=SC1091
source venv/bin/activate
pip install --upgrade pip >/dev/null
if [[ -f requirements.txt ]]; then
  pip install -r requirements.txt || warn "部分 Python 依赖安装失败（常见于 impacket/angr 等），将继续部署"
fi
deactivate || true

# 6. Go 依赖 + 编译
info "下载 Go 依赖 ..."
env -u GOFLAGS go mod download || warn "go mod download 未完全成功，尝试继续构建"

info "编译 SecAutoMind（CGO_ENABLED=0，免 cgo） ..."
CGO_ENABLED=0 go build -trimpath -ldflags "-w -s" -o secautomind-ai ./cmd/server
ok "编译完成: $(ls -lh secautomind-ai | awk '{print $9, $5}')"

# 7. 运行环境变量文件（API Key 零落盘：config.yaml 里是 ${ENV} 占位）
if [[ ! -f "$ENV_FILE" ]]; then
  info "生成环境变量文件 $ENV_FILE（占位注释，请填入真实 Key） ..."
  cat > "$ENV_FILE" <<'EOF'
# SecAutoMind 运行时环境变量。config.yaml 中的 ${VAR} 占位由此注入，避免密钥落盘。
# 填好保存后执行：systemctl restart secautomind
#
# 默认通道（config.yaml: ai.default_channel 指向的通道）对应的 Key 必须填写：
# DASHSCOPE_API_KEY=      # 阿里云百炼 / 千问 AI（通道 qwen-max）
# DEEPSEEK_API_KEY=       # DeepSeek（通道 deepseek）
# ARK_API_KEY=            # 火山方舟（通道 ark）
# MOONSHOT_API_KEY=       # Moonshot（通道 moonshot）
# ZHIPU_API_KEY=          # 智谱 GLM（通道 zhipu）
# QIANFAN_API_KEY=        # 百度千帆（通道 qianfan）
# SILICONFLOW_API_KEY=    # SiliconFlow（通道 siliconflow）
# OPENAI_API_KEY=         # OpenAI（通道 openai）
EOF
  chmod 0600 "$ENV_FILE"
else
  info "环境变量文件已存在，保持不动: $ENV_FILE"
fi
if ! grep -qE '^[A-Z_]+=.+' "$ENV_FILE"; then
  warn "$ENV_FILE 中尚无任何已填写的 Key —— 服务能启动，但所有 AI 通道都不可用！"
  warn "请执行：vi $ENV_FILE  → 填入默认通道的 Key → systemctl restart $SERVICE_NAME"
fi

# 8. systemd 服务
info "写入 systemd 服务 ..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=SecAutoMind Multi-Agent Security Platform
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=-$ENV_FILE
Environment="PATH=$PROJECT_DIR/venv/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# --http：强制主站走明文 HTTP，由 nginx 终结 TLS（config.yaml 默认 tls_enabled: true + 自签证书）
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
systemctl enable "$SERVICE_NAME"

# 9. 启动 + 健康检查
info "启动 SecAutoMind 服务 ..."
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl start "$SERVICE_NAME"

HEALTH_URL="http://127.0.0.1:${APP_PORT}/"
HEALTH_OK=0
for i in $(seq 1 15); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$HEALTH_URL" || true)"
  if [[ "$code" == "200" ]]; then HEALTH_OK=1; break; fi
  sleep 2
done

if ! systemctl is-active --quiet "$SERVICE_NAME"; then
  err "服务未运行，查看日志：journalctl -u $SERVICE_NAME -n 80 --no-pager"
  exit 1
fi
if (( HEALTH_OK == 1 )); then
  ok "服务已启动，健康检查通过：$HEALTH_URL → HTTP 200"
else
  warn "服务在运行，但 $HEALTH_URL 未返回 200（当前 code=${code:-无响应}）"
  warn "排查：journalctl -u $SERVICE_NAME -n 80 --no-pager ；并确认 config.yaml 中 server.port=$APP_PORT"
fi

# 10. 首次管理员密码（只打印一次，务必立即记录）
warn "首次启动的管理员密码只在启动日志中出现一次，现在读取："
journalctl -u "$SERVICE_NAME" -n 200 --no-pager 2>/dev/null | grep -iE "admin|password|密码" | tail -5 || true
warn "如需重置：cd $PROJECT_DIR && ./secautomind-ai -config config.yaml --reset-admin-password"

# 11. nginx 反向代理
UPSTREAM="http://127.0.0.1:${APP_PORT}"
mkdir -p "$(dirname "$NGINX_SITE")"
rm -f "$NGINX_SITE"

# 公共 location 块：两个分支复用，避免无域名/有域名两处配置各改一半而漂移。
# 注意用**带引号**的 heredoc，让 nginx 变量（$http_upgrade / $host 等）保持字面量；
# 只有 __UPSTREAM__ 占位符需要被替换成真实上游地址。
PROXY_TMP="$(mktemp)"
cat > "$PROXY_TMP" <<'NGINX_PROXY_EOF'

    # ---- 上传体积 ----
    # nginx 默认 client_max_body_size 只有 1MB：任何 >1MB 的附件/zip 上传都会被
    # nginx 直接挡成 413 Request Entity Too Large，前端表现为"上传失败"。
    # 应用侧解压上限是 总体积 200MB / 单文件 50MB（internal/handler/chat_uploads.go），
    # 上传的压缩包本身不受该限制，这里给足余量。
    client_max_body_size 512m;
    client_body_timeout 300s;

    # ---- 基础安全头 ----
    server_tokens off;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;

    location / {
        proxy_pass __UPSTREAM__;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # ---- SSE 实时流（关键）----
        # 本应用有 3 处 text/event-stream：agent.go / eino_single_agent.go / c2.go。
        # 前两者在应用内设了 X-Accel-Buffering: no，但 c2.go 的 EventStream **没有**，
        # 全靠这里关闭缓冲兜底。不关的话事件会被 nginx 攒住，前端"实时进度"变成
        # 一次性吐完，答辩演示的"实时性"卖点直接失效。
        proxy_buffering off;
        proxy_cache off;
        proxy_request_buffering off;
        chunked_transfer_encoding on;

        # ---- 长任务超时 ----
        # Agent 循环 / 多智能体编排可能持续数分钟，默认 60s 会把连接掐断。
        proxy_connect_timeout 10s;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
NGINX_PROXY_EOF
sed -i "s|__UPSTREAM__|${UPSTREAM}|g" "$PROXY_TMP"

if [[ -n "$DOMAIN" ]]; then
  # 关键：**先只写 80 端口的明文站点**，让 nginx 配置一定合法；
  # 再由 certbot --nginx 去申请证书并自动注入 443/SSL 段。
  # （若先手写 443 段并指向尚不存在的证书文件，nginx -t 会直接失败。）
  info "配置 nginx HTTP 站点（域名: $DOMAIN），随后由 certbot 补 HTTPS ..."
  cat > "$NGINX_SITE" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
EOF
  cat "$PROXY_TMP" >> "$NGINX_SITE"
  echo "}" >> "$NGINX_SITE"
else
  info "配置 nginx HTTP 站点（无域名） ..."
  cat > "$NGINX_SITE" <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
EOF
  cat "$PROXY_TMP" >> "$NGINX_SITE"
  echo "}" >> "$NGINX_SITE"
fi
rm -f "$PROXY_TMP"

if [[ -n "$NGINX_LINK" ]]; then
  ln -sf "$NGINX_SITE" "$NGINX_LINK"
  rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
fi

nginx -t
systemctl enable nginx >/dev/null 2>&1 || true
systemctl reload nginx || systemctl restart nginx
ok "nginx 反向代理已生效（$UPSTREAM）"

# 11.1 有域名：申请证书（certbot --nginx 自动注入 SSL 配置并 reload）
if [[ -n "$DOMAIN" ]]; then
  command -v certbot >/dev/null 2>&1 || pkg_install certbot python3-certbot-nginx
  info "申请 Let's Encrypt 证书（要求 $DOMAIN 已解析到本机公网 IP） ..."
  if certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect; then
    ok "HTTPS 已配置: https://$DOMAIN"
  else
    warn "证书申请失败：请确认域名解析已生效、安全组已放行 80/443，然后重跑：certbot --nginx -d $DOMAIN"
  fi
fi

# 12. 收尾提示
echo
info "部署完成"
ok   "本机访问:   http://127.0.0.1:${APP_PORT}"
if [[ -n "$DOMAIN" ]]; then
  ok "公网访问:   https://$DOMAIN"
else
  ok "公网访问:   http://YOUR_PUBLIC_IP  （需安全组放行 80）"
fi
warn "安全组只放行 22 / 80 / 443；**不要**放行 ${APP_PORT}（Go 服务端口）与 8081（MCP 端口）"
warn "AI Key 请在 $ENV_FILE 中注入（config.yaml 用 \${ENV} 占位，密钥不落盘），改完 systemctl restart $SERVICE_NAME"
warn "常看日志: journalctl -u $SERVICE_NAME -f -n 200"
warn "终审前：拿到安恒 AI 安全网关地址后，把 config.yaml 的 ai.gateway 段 enabled 置 true 并填 base_url/api_key"
warn "        自检命令：bash scripts/verify_gateway.sh --base-url <网关> --api-key <Key>"
