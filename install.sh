#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo '请以 root 运行' >&2; exit 1; }
install_deps=0
audit_timer=0
for option in "$@"; do
  case "$option" in
    --deps) install_deps=1 ;;
    --audit-timer) audit_timer=1 ;;
    *) echo '用法: bash install.sh [--deps] [--audit-timer]' >&2; exit 1 ;;
  esac
done
if [[ $install_deps -eq 1 ]]; then
  command -v apt-get >/dev/null || { echo '--deps 只支持 Debian/Ubuntu，请手动安装 Python 3.9+、nftables、iproute2' >&2; exit 1; }
  apt-get update
  apt-get install -y python3 nftables iproute2
fi
for dependency in python3 nft ip ss; do
  command -v "$dependency" >/dev/null || { echo "缺少 $dependency；Debian/Ubuntu 可执行 bash install.sh --deps" >&2; exit 1; }
done
python3 -c 'import sys; assert sys.version_info >= (3, 9), "需要 Python 3.9+"'
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
install -d -m 755 /opt/vps-safe /opt/vps-safe/audit /opt/vps-safe/docs /opt/vps-safe/third_party
install -m 755 "$source_dir/vps_safe.py" "$source_dir/vps-safe.sh" /opt/vps-safe/
install -m 644 "$source_dir/audit/nat_safe.py" "$source_dir/audit/rfw_audit.py" "$source_dir/audit/rules.json" "$source_dir/audit/config.example.json" /opt/vps-safe/audit/
install -m 644 "$source_dir/docs/rfw-rules.md" /opt/vps-safe/docs/
install -m 644 "$source_dir/third_party/RFW-LICENSE-MIT.txt" /opt/vps-safe/third_party/
install -d -m 700 /etc/vps-safe /var/lib/vps-safe /var/log/vps-safe
if [[ ! -e /etc/vps-safe/config.json ]]; then
  python3 - "$source_dir/config.example.json" <<'PY'
import sys,json,subprocess
from pathlib import Path
sys.path.insert(0,'/opt/vps-safe')
import vps_safe as v
c=json.loads(Path(sys.argv[1]).read_text());devs=set()
for family in ['-4','-6']:
 p=subprocess.run(['ip','-j',family,'route','show','default'],capture_output=True,text=True)
 if p.returncode==0:
  devs.update(r['dev'] for r in json.loads(p.stdout) if r.get('dev') and r['dev']!='lo')
c['wan_interfaces']=sorted(devs)
c['management_tcp_ports']=sorted({22}|v.detected_ssh_ports())
v.save('/etc/vps-safe/config.json',c)
PY
fi
if [[ ! -e /etc/vps-safe/audit.json ]]; then
  install -m 600 "$source_dir/audit/config.example.json" /etc/vps-safe/audit.json
fi
if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then
  install -m 644 "$source_dir/systemd/"* /etc/systemd/system/
  systemctl daemon-reload
  if [[ $audit_timer -eq 1 ]]; then systemctl enable --now vps-safe-audit.timer; fi
elif [[ $audit_timer -eq 1 ]]; then
  echo '当前没有 systemd，无法启用定时器；可手动运行 audit。' >&2
  exit 1
fi
echo '已安装到 /opt/vps-safe；尚未加载任何防火墙规则。'
echo '1. python3 /opt/vps-safe/vps_safe.py doctor'
echo '2. 检查 /etc/vps-safe/config.json 中的网卡、SSH 及允许端口'
echo '3. python3 /opt/vps-safe/vps_safe.py check'
echo '4. python3 /opt/vps-safe/vps_safe.py apply'
echo '5. 另开 SSH 验证后，执行输出中的 confirm_command。'
