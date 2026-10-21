#!/usr/bin/env bash
# ctf4_lab.sh — LAMPSecurity CTF4 靶机启停助手（VirtualBox + NAT 端口转发）
#
# 用法：
#   bash scripts/ctf4_lab.sh start    # 首次会复制 VMDK 并建 VM，然后启动
#   bash scripts/ctf4_lab.sh status   # 运行状态 + 端口转发
#   bash scripts/ctf4_lab.sh stop     # 关机（先 ACPI，超时再断电）
#   bash scripts/ctf4_lab.sh url      # 打印访问地址
#
# 可用环境变量覆盖：
#   CTF4_SRC   原始 VMDK 路径（默认 E:/Code/Cyber range/ctf4/CTF4/CTF4.vmdk）
#   CTF4_WORK  工作目录（默认 E:/Code/Cyber range/ctf4_work）
#   VBOX       VBoxManage 路径（默认自动探测）
#   CTF4_VM    虚拟机名（默认 CTF4）
#
# 设计说明：原 .vmx 用 host-only，但本机 VirtualBox 7.2.14 的 host-only NDIS 过滤驱动
# 未加载（VERR_INTNET_FLT_IF_NOT_FOUND），故改用 NAT + 端口转发，不依赖宿主驱动。
set -u

CTF4_SRC="${CTF4_SRC:-E:/Code/Cyber range/ctf4/CTF4/CTF4.vmdk}"
CTF4_WORK="${CTF4_WORK:-E:/Code/Cyber range/ctf4_work}"
CTF4_VM="${CTF4_VM:-CTF4}"
HTTP_PORT="${HTTP_PORT:-8080}"
SSH_PORT="${SSH_PORT:-2222}"

if [ -z "${VBOX:-}" ]; then
  for c in "/c/Program Files/Oracle/VirtualBox/VBoxManage.exe" \
           "$(command -v VBoxManage 2>/dev/null || true)"; do
    [ -n "$c" ] && [ -x "$c" ] && VBOX="$c" && break
  done
fi
[ -n "${VBOX:-}" ] && [ -x "$VBOX" ] || { echo "[FAIL] 未找到 VBoxManage，请设 VBOX=<路径>" >&2; exit 1; }

vm_exists() { "$VBOX" showvminfo "$CTF4_VM" >/dev/null 2>&1; }
vm_running() { "$VBOX" list runningvms 2>/dev/null | grep -q "\"$CTF4_VM\""; }

# 幂等加转发：先删同名再建，避免 "already exists"
add_pf() {
  local name="$1" host="$2" guest="$3"
  "$VBOX" controlvm "$CTF4_VM" natpf1 delete "$name" >/dev/null 2>&1
  "$VBOX" controlvm "$CTF4_VM" natpf1 "${name},tcp,,${host},,${guest}" >/dev/null 2>&1 \
    && echo "  [ok] ${name}: 宿主 ${host} -> 客机 ${guest}" \
    || echo "  [warn] ${name} 转发设置失败（VM 可能未运行）"
}

do_start() {
  if ! vm_exists; then
    [ -f "$CTF4_SRC" ] || { echo "[FAIL] 找不到原始 VMDK: $CTF4_SRC" >&2; exit 1; }
    mkdir -p "$CTF4_WORK"
    if [ ! -f "$CTF4_WORK/CTF4.vmdk" ]; then
      echo "[1/4] 复制 VMDK（保护原件）..."
      cp "$CTF4_SRC" "$CTF4_WORK/CTF4.vmdk" || { echo "[FAIL] 复制失败" >&2; exit 1; }
      a=$(stat -c%s "$CTF4_SRC"); b=$(stat -c%s "$CTF4_WORK/CTF4.vmdk")
      [ "$a" = "$b" ] || { echo "[FAIL] 复制后大小不一致 ($a != $b)" >&2; exit 1; }
      echo "      大小校验一致: $b 字节"
    fi
    echo "[2/4] 创建虚拟机 $CTF4_VM ..."
    "$VBOX" createvm --name "$CTF4_VM" --ostype RedHat --register \
      --basefolder "$CTF4_WORK" >/dev/null || { echo "[FAIL] 创建失败" >&2; exit 1; }
    echo "[3/4] 配置（LSILogic SCSI / e1000 / NAT）..."
    "$VBOX" modifyvm "$CTF4_VM" --memory 512 --vram 16 --cpus 1 >/dev/null
    "$VBOX" modifyvm "$CTF4_VM" --nic1 nat --nictype1 82540EM >/dev/null
    "$VBOX" modifyvm "$CTF4_VM" --audio none --usb off --boot1 disk >/dev/null 2>&1
    "$VBOX" storagectl "$CTF4_VM" --name SCSI --add scsi --controller LSILogic >/dev/null
    "$VBOX" storageattach "$CTF4_VM" --storagectl SCSI --port 0 --device 0 \
      --type hdd --medium "$CTF4_WORK/CTF4.vmdk" >/dev/null || { echo "[FAIL] 挂盘失败" >&2; exit 1; }
  else
    echo "[1/4] 虚拟机已存在，跳过创建"
    echo "[2/4] -"
    echo "[3/4] -"
  fi

  if vm_running; then
    echo "[4/4] 已在运行"
  else
    echo "[4/4] 启动（headless）..."
    "$VBOX" startvm "$CTF4_VM" --type headless >/dev/null || { echo "[FAIL] 启动失败" >&2; exit 1; }
  fi

  # 等 eth0 取到 DHCP 再挂转发
  sleep 8
  echo "端口转发："
  add_pf http  "$HTTP_PORT" 80
  add_pf ssh   "$SSH_PORT"  22
  add_pf mysql "3307" 3306
  echo ""
  echo "就绪后访问： http://127.0.0.1:${HTTP_PORT}/   （客机引导约 20-40s）"
}

do_status() {
  if vm_running; then echo "状态: 运行中"; else echo "状态: 未运行"; fi
  vm_exists || { echo "(虚拟机未创建)"; return; }
  echo "端口转发:"
  "$VBOX" showvminfo "$CTF4_VM" --machinereadable 2>/dev/null | grep -i '^Forwarding' | sed 's/^/  /'
  echo "HTTP 探测:"
  code=$(curl -s -o /dev/null -m 8 -w '%{http_code}' "http://127.0.0.1:${HTTP_PORT}/" 2>/dev/null || echo "000")
  echo "  http://127.0.0.1:${HTTP_PORT}/ -> ${code}"
}

do_stop() {
  if ! vm_running; then echo "未运行，无需关机"; return; fi
  echo "发送 ACPI 关机信号..."
  "$VBOX" controlvm "$CTF4_VM" acpipowerbutton >/dev/null 2>&1
  for i in $(seq 1 20); do
    sleep 2
    vm_running || { echo "已关机"; return; }
  done
  echo "ACPI 超时，强制断电"
  "$VBOX" controlvm "$CTF4_VM" poweroff >/dev/null 2>&1
  sleep 2
  vm_running && echo "[WARN] 仍未关闭" || echo "已关机"
}

case "${1:-}" in
  start)  do_start  ;;
  status) do_status ;;
  stop)   do_stop   ;;
  url)    echo "http://127.0.0.1:${HTTP_PORT}/" ;;
  *)      echo "用法: bash scripts/ctf4_lab.sh {start|status|stop|url}" >&2; exit 2 ;;
esac
