# 来源快照

防滥用代码 `audit/nat_safe.py`、`audit/rfw_audit.py`、`audit/rules.json` 与对应测试，基于本次会话中为同一项目所有者编写的 NAT Safe 工作副本；基础提交为 `zhangx16/nat-safe@0b2fe0738cb369e9499fa5f6c34e471012e4f3cc`。

该快照包含已验证的 RFW 扩展（SMTP 审计、可选协议采样、来源国家策略审计、RFW 累计日志导入）及 SMTP 方向回归测试。防火墙核心 `vps_safe.py` 为本项目新增，与审计模块分离。

RFW 上游核对提交：`narwhal-cloud/rfw@a887824c7738521aa7e6459f9817317c156723c3`。相关 FET 豁免/阈值按上游提供的 MIT 选项复用，许可文本保留在 `third_party/RFW-LICENSE-MIT.txt`。没有打包或安装 eBPF 二进制。
