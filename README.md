# VPS Safe — VPS 防火墙与防滥用脚本

用于 Linux VPS / NAT 宿主机的 **nftables 防火墙 + 容器防滥用巡检**。适配 Podman、Docker、Incus，并包含独角鲸 Narwhal Agent 端口映射归属。

- **防火墙**：IPv4/IPv6 来源封禁、端口封禁、可选宿主机入站白名单、SMTP 出站限制、按来源 SYN 速率限制、容器 IP 隔离。
- **防滥用**：14 类进程/启动项规则、认证代理复核、SMTP 外连、可选 HTTP/SOCKS5/WireGuard/QUIC/FET 观察、多地区多人共享线索。
- **可审阅与恢复**：先渲染/检查；显式 apply 后默认 120 秒未确认自动回滚；只管理自己的 `inet vps_safe` 表，不执行全局 `flush ruleset`。
- **报告**：防火墙事务、前后规则及恢复记录；巡检 JSON / Markdown / HTML 私有报告。

安装不会自动加载防火墙，不会自动停客户容器；正常代理协议、多地区 IP、工具名称命中不直接等同违规。

## 安装（Debian / Ubuntu，root）

需要 Linux、Python 3.9+、nftables、iproute2。基础审计不依赖 pip，不需要 Git：

```bash
apt-get update && apt-get install -y curl tar python3 nftables iproute2 &&
work_dir="$(mktemp -d /root/vps-safe-download.XXXXXX)" &&
curl -fL --retry 3 https://codeload.github.com/zhangx16/vps-safe/tar.gz/refs/heads/main -o "$work_dir/source.tar.gz" &&
tar -xzf "$work_dir/source.tar.gz" -C "$work_dir" &&
cd "$work_dir/vps-safe-main" &&
bash install.sh
```

也可 `git clone https://github.com/zhangx16/vps-safe.git` 后执行 `bash install.sh --deps`。`--deps` 只支持 Debian/Ubuntu，其他发行版自行安装上述依赖。root 无需 `sudo`。

安装到 `/opt/vps-safe/`，配置 `/etc/vps-safe/config.json`。首次安装从默认路由检测 WAN 网卡，从当前 SSH 会话和 sshd 监听探测管理端口；更新不覆盖已有配置。默认不启用防火墙开机加载；加 `--audit-timer` 只启用每分钟的只读巡检。

## 先检查，再应用

```bash
python3 /opt/vps-safe/vps_safe.py doctor
cat /etc/vps-safe/config.json
python3 /opt/vps-safe/vps_safe.py render --output /root/vps-safe-preview.nft
python3 /opt/vps-safe/vps_safe.py check
python3 /opt/vps-safe/vps_safe.py apply
```

也可以在项目目录用 `./vps-safe.sh ...`；直接运行不带参数会显示帮助，不会套用防火墙。

`apply` 会输出事务 ID 和 `confirm_command`。**另开 SSH 会话并测试必要业务**后，在 120 秒内执行输出的确认命令：

```bash
python3 /opt/vps-safe/vps_safe.py confirm --transaction 输出中的事务ID
```

未确认会通过独立 systemd 定时任务恢复之前的本项目规则。回滚代码保存在私有状态目录，不依赖当前终端持续连接，也不因源码目录移动而丢失。没有 systemd 或运行在不同网络命名空间时，默认拒绝应用；只有明确具备控制台时，才考虑 `apply --no-auto-rollback`。该参数需要手动确认或回滚。

管理端口优先于本项目来源/端口封禁；应用时自动加入当前 SSH 服务端口并校验冲突。但其他防火墙/XDP/云安全组仍可阻断这些端口，**本脚本不能保证覆盖其他管理器的判定**。必要 DHCP、IPv6 邻居发现与路径 MTU 控制报文保留。

## 防火墙配置

完整字段见 [`config.example.json`](config.example.json)。`wan_interfaces` 必须是实际 WAN 网卡（如 `ens18`，不要照抄 `eth0`）。

|字段|含义|默认|
|---|---|---|
|management_tcp_ports|始终保留的管理 TCP 端口|22，应用时附加实际 SSH 端口|
|host_default_drop|限制 WAN 到宿主机未允许端口；不代替容器端口发布规则|false|
|allow_tcp_ports / allow_udp_ports|严格宿主机入站模式下允许的业务端口|示例 TCP 80/443|
|blocked_source_cidrs|明确封禁的原始入站来源；不封正常出站会话的回复方向|空|
|blocked_tcp_ports / blocked_udp_ports|WAN 入站目标端口封禁，在 DNAT 前匹配宿主机公开端口|空|
|block_smtp / smtp_ports|阻止宿主机 OUTPUT 和容器 FORWARD 向 WAN 发起指定 SMTP 端口流量|true；25/465/587/2525|
|smtp_exempt_cidrs|允许发送邮件的源 IP/网段；基于 NAT 前的原始源地址|空|
|source_policy|来源范围 allow/deny 策略，可载入可信 GeoIP 国家 CIDR|off|
|quarantine_ips|明确隔离的单个容器 IPv4/IPv6 地址；不接受网段或宿主机自己的地址|空|
|syn_rate_per_second / syn_burst|每来源 IP 的新建 SYN 速率限制；管理端口豁免|0（关闭）/ 50|
|drop_invalid|WAN 入站丢弃 conntrack invalid|true|

SMTP 规则不禁止 POP3/IMAP 收邮件或网页邮箱。合法 SMTP 也会受影响，应明确配置例外。未承诺阻止隧道内邮件或非标准端口上的邮件。SYN 限速不是上游抗 DDoS 清洗，不抵御已占满链路的攻击；不自动把所有 UDP/QUIC/WireGuard 当作攻击。

要限制宿主机新服务暴露，可改 `host_default_drop` 为 true，并完善允许端口后按 apply/confirm 流程应用。已有 Docker/Podman/Incus NAT 和 FORWARD 规则不会被清空；`accept` 只结束本项目链，其他表仍会继续检查，`drop` 则会阻断流量。输入来源策略/端口限制在 DNAT 前按 WAN 公网目标端口匹配，避免误用容器 guest port。

### 来源范围 / 国家策略

不自动下载国家 IP 数据。可把可信 GeoIP 数据转换为 CIDR 后填入（示例是文档保留地址，不代表国家）：

```json
"source_policy": {
  "mode": "allow",
  "cidrs": ["192.0.2.0/24", "2001:db8::/32"],
  "families": [4, 6]
}
```

`allow` 模式需要每个指定 IP 家族都有范围；缺失则拒绝应用，避免意外封光 IPv6。只想限制 IPv4 时显式设置 `families: [4]`。SSH 管理端口和必要网络控制报文保留。GeoIP 数据过期或定位不准会影响实际访问，需要运营者维护；巡检用的国家策略与防火墙 CIDR 策略分别配置。

### 容器网络隔离

核实客户违规后，可从运行时读取当前容器 IP 并生成隔离事务，仍需确认：

```bash
python3 /opt/vps-safe/vps_safe.py quarantine \
  --runtime podman --container 容器完整ID或名称
```

支持 `--runtime docker` 或 `incus`。拒绝 host 网络容器、无可用 IP 的容器、宿主机自身地址。规则覆盖转发以及宿主机与容器的连接，兼顾 Narwhal 用户态端口转发；不删除容器数据、不改平台客户状态。

**隔离基于此时的 IP**：容器换 IP、销毁或地址复用后需重新评估并解除旧规则，否则可能影响后来占用该地址的容器。隔离不会杀进程，容器内部/本地 Unix socket 仍可工作。宿主机/其他管理器已开启硬件/软件 flow offload 时，已有卸载连接可能绕过常规 netfilter；需要先独立核查 offload，不能把本命令当作绝对网络隔离保证。

解除隔离：回滚该事务，或用不含隔离 IP 的原始配置重新 apply/confirm。命令行 `quarantine` 不覆盖原始配置文件；确认后仅将有效规则保存到启动状态。

## 防滥用检查与处理

```bash
python3 /opt/vps-safe/vps_safe.py audit

# 短时、被动协议采样；使用真实 WAN 网卡，不保存载荷
python3 /opt/vps-safe/vps_safe.py audit --capture-interface ens18 --capture-seconds 5

# 复核后，明确停止某容器里的挖矿程序（仅 SIGTERM）
python3 /opt/vps-safe/vps_safe.py audit --enforce \
  --select 完整容器ID --rule miner --action terminate

# 核实为被禁止的机场后端后，明确停止容器；保留全部数据
python3 /opt/vps-safe/vps_safe.py audit --enforce \
  --select 完整容器ID --rule airport-node --action stop-container
```

默认巡检报告：`/var/log/vps-safe/audit/`，可通过 `--output` 自定义。JSON、Markdown、HTML 文件权限 600，原始进程参数不写报告，避免泄露密码。报告保留 30 天。定时任务配置 `/etc/vps-safe/audit.json`。

14 类规则来自前面的 NAT Safe 项目：发包、扫描、Flood/DDoS、代理面板、挖矿、机场后端、弱加密参数、DD 重装、MTProto、跑分、自动化浏览器、撞库爆破、传统 VPN、SOCKS/开放代理程序。进程名称可能误报；`microsocks`/`danted` 配置了认证时不能直接称为匿名代理。宿主机 HOST 进程始终只审计，不能通过本工具自动终止。

多地区疑似共享默认阈值：同一容器 **5 个公网来源、3 个国家、连续 3 次且持续至少 120 秒**。只看入站使用者，排除 SSH 与出站网站/CDN；未知地区不作为违规。可选配置离线 MaxMind 数据库（需可选 `maxminddb` 包），或明确允许发送 IP 给第三方：

```bash
# 默认不联网查询 IP
python3 /opt/vps-safe/vps_safe.py audit --geo-db /path/to/GeoLite2-City.mmdb --watch 60
# 显式允许将客户公网 IP 发送给 ipwho.is
python3 /opt/vps-safe/vps_safe.py audit --geo-provider ipwhois --watch 60
```

多地区来源、HTTP/SOCKS5/QUIC/WireGuard 观察、FET 特征、SMTP 端口命中都不是直接违规结论，也不自动生成防火墙封禁。FET 需要显式 `--fet-mode strict`；详见 [RFW 规则对照](docs/rfw-rules.md)。本项目没有复制 XDP 引擎：nftables 是 L3/L4 拦截，协议 DPI 是可选短时审计，不宣称具备持续线速 DPI 拦截能力。

## 状态、回滚、停用与开机加载

```bash
python3 /opt/vps-safe/vps_safe.py status
python3 /opt/vps-safe/vps_safe.py rollback
python3 /opt/vps-safe/vps_safe.py disable
```

`rollback` 恢复当前事务前的本项目表，保留其他表。拒绝用旧事务覆盖新规则。`disable` 删除本项目表并禁用自己的开机恢复服务，不动系统其他防火墙。

确认 SSH 和业务后，可手动启用**已确认规则**的开机恢复：

```bash
systemctl enable vps-safe-firewall.service
```

该服务等待 network-online 后恢复，启动早期到恢复前存在未加载本项目规则的窗口；不会改写 `/etc/nftables.conf`，不会启停系统 nftables/firewalld/UFW。其他管理器若全局清空规则或 XDP 提前丢包，会影响实际效果。

只读巡检定时任务：

```bash
systemctl enable --now vps-safe-audit.timer
journalctl -u vps-safe-audit.service
```

## 测试与验证

```bash
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s audit/tests -v
python3 -m py_compile vps_safe.py audit/nat_safe.py audit/rfw_audit.py
bash -n install.sh vps-safe.sh
sudo unshare --net python3 tests/kernel_cases.py
```

内核集成测试只允许在隔离网络命名空间执行，创建临时 veth、模拟 WAN 和容器、验证管理访问、默认拒绝、SMTP host/forward 限制、NAT 保留、来源封禁、隔离和独立进程回滚。不会在生产网络加载测试规则。GitHub Actions 同时运行单元测试和内核集成测试。本次本地结果见 [验证记录](docs/validation.md)。

## 来源与许可

- 防滥用部分基于 [zhangx16/nat-safe](https://github.com/zhangx16/nat-safe)，打包的来源快照见 [`docs/provenance.md`](docs/provenance.md)。
- RFW 分类及 FET 阈值参考 [narwhal-cloud/rfw](https://github.com/narwhal-cloud/rfw)，保留上游 MIT 许可于 `third_party/RFW-LICENSE-MIT.txt`。
- nftables 规则语义参考 [官方手册](https://netfilter.org/projects/nftables/manpage.html) 和 [Netfilter meters 文档](https://wiki.nftables.org/wiki-nftables/index.php/Meters)。
- 项目代码采用 MIT，见 [`LICENSE`](LICENSE)。真实客户报告、IP、服务器凭据不发布到仓库。
