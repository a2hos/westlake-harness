# G301 两个官方原包主机静态清点候选

- Goal: 在已接受的 G299 raw 身份之上，为 NordVPN 与 Surfshark 各执行一次原版 APK 四阶段 ZIP / metadata / ELF / DEX 清点。
- Layer: host static inventory only。修复对象为 APK 证据层；不涉及运行时、设备或 VPN 服务验证。
- Inputs: `nordvpn/INPUTS.json` 与 `surfshark/INPUTS.json` 各自固定 APK SHA、G299 root raw admission、harness 源码、venv manifest 与 readelf。两个 APK 只经项目内只读链接交给扫描器，输出在 G301 独立目录。
- Command: `python3 -B docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g301-nord-surf-static-candidate-v1/launch_one.py <nordvpn|surfshark>`；每包一次，顺序执行，真实 argv/rc/原始流见各自 `OUTER-COMMAND.json` 与 `outer.*.raw`。
- Expected: 四阶段各 rc 0、全部 ZIP CRC、唯一 manifest、DEX/ELF 身份及 ABI 闭合、源码/APK/venv/tool 前后哈希一致。
- Observed: NordVPN outer rc 0，ZIP 3517、DEX 3、真 ELF 80（ARM64 20），11 项检查全 true；Surfshark outer rc 0，ZIP 3971、DEX 4、真 ELF 138（ARM64 37），11 项检查全 true。每阶段命令与结果均 rc 0、postguard true；原始流 SHA 已回算一致。各包 `RESULT.json`、`SOURCE-BEFORE.json`、`SOURCE-AFTER.json` 与 `phases/*` 保存逐项证据。
- Passed: 本地候选扫描通过；尚需独立终态复核和外环单独静态准入，不能自行增加 canonical 静态计数。
- Failed: None in this bounded host scan.
- Next: 独审两个输入 SHA、四阶段 rc/原始流、库存数量及前后守卫；外环按每包独立决定静态准入。黑盒资格、安装、真冷启动、上屏、交互、VPN 连接均另案。
- Resource boundary: 零容器、零 namespace、零设备、零 SSH、零 Bridge 写入；无目标编译。
