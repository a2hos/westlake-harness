# G280 Firefox 156.0 官方档案变体候选

已有 `archive.mozilla.org` HTTPS 下载收据给出 133,273,833 字节原包；本轮只读取原包，不重新下载、使用容器或访问设备。原登记期望 SHA `313626ee…a41ec6` 与实际 SHA `d9c16c74…e251c` 不同，旧失败保留；本候选只考虑独立官方变体。

ZIP 完整 CRC 检查 3,307 项全部通过，名称唯一，根 Manifest 一个、根 DEX 三个、真实 ARM64 ELF 十八个。AOSP16 R4 `aapt2` 报告 `org.mozilla.firefox`、版本 `156.0`、code `2016183650`；同版 `apksigner` 验证 v2 签名，单签名证书 SHA-256 为 `a78b62a5165b4494b2fead9e76a280d22d937fee6251aece599446b2ea319b04`。三项子命令均 rc0，精确 argv、超时、工具和输入 SHA、stdout/stderr 哈希见 `*.COMMAND.json`、`INPUTS.json` 与 `RESULT.json`。

仍需独立审阅原包、下载渠道与签名收据，并由外环决定是否把这个新变体计为原包。Mozilla 公开证书与该签名证书的外部匹配尚未证明；本轮不是完整 harness 静态扫描、安装或冷启动。权威计数变化为零，Firefox 开源客户端不进入海外主流黑盒 100 项。
