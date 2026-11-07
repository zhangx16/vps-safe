# RFW 规则总结与 NAT Safe 的实现边界

参考：[narwhal-cloud/rfw README](https://github.com/narwhal-cloud/rfw/blob/main/README.md)，并核对实际源码提交 [`a887824c7738521aa7e6459f9817317c156723c3`](https://github.com/narwhal-cloud/rfw/tree/a887824c7738521aa7e6459f9817317c156723c3)。核对文件：`rfw-common/src/lib.rs`、`rfw-ebpf/src/main.rs`、`rfw/src/main.rs`。

NAT Safe 是**审计工具**。本次合入不会加载 XDP、替换 RFW、自动开启 GeoIP、修改现有防火墙或封禁客户。协议存在不等于违规；是否允许应由机主条款决定。

## 规则对照

|RFW 类别|RFW 实际机制|NAT Safe v0.2 对应能力|默认与限制|
|---|---|---|---|
|邮件 SMTP|TCP 25、465、587、2525 端口|检查已建立或 SYN-SENT 的公网目标 SMTP 端口，报告 `smtp-egress`|默认启用；端口线索不能证明 SMTP 内容或垃圾邮件；不将 POP3/IMAP 算发送邮件|
|HTTP 入站|请求方法前缀识别|可选被动采样识别完整方法+空格，非标准端口也可识别；`protocol-http`|默认不抓包；仅明文，不将 TLS 当 HTTP|
|SOCKS5 入站|SOCKS5 握手特征|可选识别客户端版本、认证方法数量及方法列表；`protocol-socks5`|握手不代表服务器接受，更不能证明匿名开放；认证还看原进程检测|
|FET 全加密流量|TLS/HTTP/前六字节可打印豁免；前 16–32 字节平均 popcount 严格在 3.4–4.6 之间时，strict 判定、loose 放行|`--fet-mode strict` 可报告 `protocol-fet`；仅已观察到 SYN 后的首个载荷参与判断|默认 off；loose 不产生此项；不是 Shannon 熵、不是 Shadowsocks/V2Ray 身份证明；不自动处置|
|WireGuard|消息类型、保留零字节、握手包长度|UDP 特征采样：握手 148/92/64 字节，数据消息至少 32 字节且 16 字节对齐；`protocol-wireguard`|协议观察，不等于攻击；需要完整未分片包|
|QUIC|v1/v2、版本协商、Google QUIC、长/短头部特征|UDP 支持 v1/v2/版本协商和保守的 Google QUIC 特征；短头必须先在同一方向流中见到长头；`protocol-quic`|避免把任意 0x40 UDP 都识别成 QUIC；不等于代理，普通 HTTP/3 也使用 QUIC|
|GeoIP 黑名单|指定国家触发协议过滤或全部过滤|配置 `country_policy.mode=deny`，报告入站来源国家策略不符|只审计；未知国家不算违规；需要 GeoIP|
|GeoIP 白名单|只允许指定国家|配置 `country_policy.mode=allow`，报告已知且不在名单的入站来源|不影响宿主机 SSH；不会创建防火墙规则|
|所有入站 block-all|XDP 最高优先级丢弃匹配来源流量|对应审计全部已识别容器入站来源的国家策略|不迁移全局丢包开关，避免锁死宿主机和客户|
|端口访问日志|BPF LRU 中累计 Allowed/Blocked，最多 65536 项|导入未分组的 `rfw stats` 文本；归属容器、保存累计计数和增量|原始 map 没有具体 DPI 原因、会话活跃时间，不能从 Blocked 推定客户违规，也不参与在线用户/地区计数|

## README 与源码差异

1. README 将邮件规则描述为“只阻止发送”；核对的 eBPF 实现实际同时检查 SMTP **源端口与目标端口**。XDP 在入站路径丢弃邮件服务返回包，也可能间接阻断出站会话。NAT Safe 独立从容器 TCP socket 的**公网目标端口**判断外连，避免把所有 SMTP 服务监听都算垃圾邮件。
2. FET 的 strict/loose 不是两个训练模型。核对的函数在通过豁免后，最终返回 `strict_mode`；loose 情况没有把随机特征判为阻断。本项目按此语义保留 strict 观察与 loose 放过，并清楚标为推断。
3. 上游提供的端口 map 只有源 IP、目标端口、传输层协议、累计放行/阻断数；没有“触发了 HTTP 还是 QUIC”的字段。导入统计不会伪造协议归因。
4. 核对的上游版本只处理 IPv4。NAT Safe 原有进程/连接检查支持 IPv6；新增采样解码支持基本 IPv6 TCP/UDP，但跳过扩展头与碎片，不能宣称全 IPv6 DPI。

## 可选短时被动协议观察

```bash
# 查看网卡名，使用实际公网网卡
ip -br link

# 采样至多 5 秒或 5000 包；不保存 PCAP、载荷、HTTP URL 或 SOCKS 认证内容
sudo python3 nat_safe.py --capture-interface eth0 --capture-seconds 5 --max-packets 5000

# 明确开启 FET 统计启发式；默认 off
sudo python3 nat_safe.py --capture-interface eth0 --fet-mode strict
```

采样使用 Linux AF_PACKET，无混杂模式、无数据包注入、不加载 eBPF；需要 root/CAP_NET_RAW。只统计公网来源的接收方向，排除宿主机发出的包和 SSH/管理端口（包括独角鲸映射到容器 22 的端口）。只保存协议类别、端口、包数、来源数和容器归属。

**不具备 TCP 重组或 XDP 的实时持续检测能力**。抓取窗口内没有新连接时，FET 可能没有样本；分段握手、IPv4/IPv6 碎片、IPv6 扩展头、网卡 offload、隧道或截断均可能漏检。采样包数包含被跳过帧，达到上限会提前停止；不能将其当全天流量比例。已经被 XDP 丢弃的包不会再到 AF_PACKET。

独角鲸端口映射可定位容器；不能归属的公网端口标为 `HOST`/`host-unattributed`，不会猜测归属。当前新增 DPI 没有完整的 Docker/Incus NAT conntrack 归属能力，**不能将 HOST 观察直接归咎给某个容器**。

这些新网络规则与跨地区线索一样，不能通过 `--enforce` 直接处罚。原有经人工核实的进程规则仍可显式处置；需要实时协议拦截时，应由运营者独立部署和配置 RFW，而不是让定时审计隐式接管整机网络。

## 国家策略

`config.json` 示例（不填则 off）：

```json
{
  "country_policy": {
    "mode": "deny",
    "countries": ["CN", "RU"],
    "containers": []
  }
}
```

`containers` 为空表示全部已归属容器；也可填写报告中的完整运行时 ID。只接受大写两位国家代码。依旧需要 `--geo-db` 或显式同意的 `--geo-provider ipwhois`；无地理数据、查询失败不当作违规，报告包含 unknown_ips。

## 导入现有 RFW 的端口统计

```bash
# 已部署 RFW 且已启用 --log-port-access；本项目不负责启动/改写它
sudo sh -c 'umask 077; rfw stats > /root/rfw-stats.txt'
sudo python3 nat_safe.py --rfw-stats /root/rfw-stats.txt
```

使用默认未分组表格，支持字段 `Source IP / Proto / Port / Allowed / Blocked / Total`。支持最多 8 MiB 文件。首次导入增量为 null；下一次按同一 `--state-dir` 计算 Blocked 增量；计数下降当作重置，增量仍为 null。导入数据中大量历史探测 IP 不作为“多人正在用机场”的证据。

## 许可与来源

FET 豁免/阈值与规则分类参考上述 RFW 提交，选择其提供的 MIT 许可。保留上游 MIT 文本于 [`third_party/RFW-LICENSE-MIT.txt`](../third_party/RFW-LICENSE-MIT.txt)。未打包或安装上游 eBPF 二进制，也未搬运其 Rust/XDP 加载器。
