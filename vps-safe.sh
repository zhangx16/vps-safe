#!/usr/bin/env bash
set -euo pipefail
command -v python3 >/dev/null || { echo '缺少 Python 3；Debian/Ubuntu: apt-get install python3' >&2; exit 1; }
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$script_dir/vps_safe.py" "$@"
