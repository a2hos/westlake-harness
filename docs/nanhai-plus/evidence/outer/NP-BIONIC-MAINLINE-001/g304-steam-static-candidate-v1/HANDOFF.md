# G304 Valve Steam 两包四阶段主机静态扫描候选

## Boundary
- Boundary: APK Package/Resource、DEX 与 ARM64/native ELF 主机静态证据；不触及 App 运行、OH7 服务、Bionic 构建图、设备或 Bridge。
- Android behavior: 清点 Valve 原版 Steam Mobile 与 Steam Link APK 的 ZIP、manifest/metadata、ELF 和 DEX。
- OpenHarmony mapping: 本次无 OH 映射或设备执行；扫描结果只供后续问题簇分析。
- Fix layer: 证据与工具层，未新增 shim、stub、bypass。

## Evidence target
- What this proves: 两个 G302 root 准入原包各执行一次四阶段主机扫描，原始命令/rc/流、前后守卫、DEX/ELF 逐项库存可复核。
- What this does not prove: 黑盒资格、canonical 静态准入、安装、冷启动、上屏、Steam 服务功能或 Bionic/OH7 适配成功。

## Environment
- Host: 本机 macOS，项目 `NANHAI_PROJECT_ROOT` 环境入口；无网络扫描、SSH、容器或 namespace。
- Device: 无设备调用，既有 HOLD 与设备排除规则不变。
- Tool path: G301 已接受的方法为参考；本目录独立 `launch_one.py`、各包 `run.py`/`scan_phase.py`/`common.py`，输入固定项目 venv manifest、harness 源码与 OH SDK `llvm-readelf` SHA。
- Artifact path: 本目录 `steam_mobile/`、`steam_link/` 保存命令、原始流、四阶段结果、前后守卫；G302 staging 原包仅只读软链接输入。
- App: `com.valvesoftware.android.steam.community` 3.10.9 与 `com.valvesoftware.steamlink` 1.3.32，原包 SHA 见 `CANDIDATE.json`。

## Status
- Label: `build_pass` 仅指主机静态扫描候选；并非 Android target build 或设备通过。
- Why: 两包外层与 ZIP/metadata/ELF/DEX 共八阶段实际 rc0，仍待独立终态与 root 静态准入。

## Observed wall
- Classification: none in bounded host scan.
- Fact: Steam Mobile 外层 rc0，1816 ZIP 全 CRC、4 DEX、100 真 ELF（25 ARM64）；Steam Link 外层 rc0，134 ZIP 全 CRC、1 DEX、96 真 ELF（24 ARM64）。各包 12 项结果检查全 true；源码、APK、venv、readelf 前后守卫字节一致。
- Evidence: `CANDIDATE.json`、各包 `OUTER-COMMAND.json`、`outer.*.raw`、`RESULT.json`、`SOURCE-BEFORE.json`、`SOURCE-AFTER.json`、`phases/*/{COMMAND,RESULT}.json` 与 `stdout.raw`/`stderr.raw`。
- First failing command: None.
- Exit/status: 两个真实外层命令均 rc0；未增加 canonical 静态计数。

## Hypotheses
- Candidate: 这些逐项库存可用于按常见 ELF/DEX 依赖聚类后选择一项桥接修复；静态库存不能预测冷启动通过。
- Cheapest falsifier: 独立复算库存/源守卫与原包 SHA，再检查后续真实启动墙是否落在这些依赖上。
- Blocking: no

## Proven
- G302 root raw 准入 SHA `bd63045a19277cec49fe1f71630b12a9bb3a6cf983869b50cf4c738dcebef02e` 被两包 `INPUTS.json` 固定。
- 两包分别一次扫描，四阶段命令、返回码、原始流与前后守卫保存；宿主工具读取原包而未修改原字节。
- `EVO31-MEASUREMENTS.json` 记录静态分支实际开始/结束与 wall；CPU 未采集，资格分支尚未合并，不推算吞吐增益。

## Not proven
- 独立终态/root 静态准入、发布者证书指纹绑定、黑盒资格、APK 冷启动、图形/输入、设备验收。

## Failed
- 本次界定的两份主机扫描无失败阶段。若独审发现输入或库存漂移，保留原始结果并新版本修订，不重放同一尝试。

## Next evidence
- Command: 独立复核两个 `INPUTS.json` 与 raw root SHA、八阶段原始流/rc、库存、工具调用和前后守卫；root 再逐包决定静态准入。
- Expected output: 每包独立 peer 收据与 root 静态接受或拒绝，不从候选自动改 `TASK-SUMMARY`。
- If it fails: 定位精确阶段/原始流，维持候选状态，另建版本化工作包。

## Shim/stub/bypass inventory
- Item: 无。
- Owner: G304 主机扫描 peer。
- Why it exists: 仅做库存证据。
- Removal condition: 不适用。
- Test coverage: 八阶段真实主机执行、12 项结果检查和完整前后守卫；无设备测试。
- App-specific or common: 扫描流程通用，输入 SHA 与包身份逐包固定。

## Memory/skill/CI/review updates
- Memory: 未请求更新。
- Skill: 使用 WestLake 证据层级和不把 host pass 记作 device pass 的纪律。
- CI: 本次是隔离本机一次性扫描；未更改 CI。
- Review checklist: 精确 APK/raw root、扫描器源码、venv/readelf、四阶段 rc 与 raw SHA、ZIP 全 CRC、metadata 包版本、ELF ABI、DEX 身份、前后守卫、EVO31 时间与所有零设备/容器/namespace/Bridge 边界。
