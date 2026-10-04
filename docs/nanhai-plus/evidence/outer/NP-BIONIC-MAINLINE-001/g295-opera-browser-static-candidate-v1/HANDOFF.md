# G295 Opera Browser 官方原包四阶段主机静态扫描

## Boundary
- Boundary: Package 与 Tooling。
- Package 与 Tooling；只读扫描已接收的 `com.opera.browser` 原版 APK，不修改桥接实现。
- Android behavior: 原包包名、版本、DEX 和 ARM64 ELF 字节应如实盘点。
- OpenHarmony mapping: 此次只生成主机证据；OH 服务与 App 单 Bionic 运行另行验证。
- Fix layer: 主机静态证据层。

## Evidence target
- What this proves: 当前 Mac 原生宿主上，对 SHA-256 `fd2b2e3578d7c6e3fdb9f0f9b932b315d9e2612bc68f073169f422c6ed5dcce6` 的官方原包完成 ZIP、metadata、ELF、DEX 四阶段清点。
- What this does not prove: 安装、启动、上屏、输入、Bionic 运行、黑盒资格、设备验收或桥接功能。

## Environment
- Host: 当前 Mac 原生宿主；通过 `scripts/nanhai_plus_env.py --run` 注入 `NANHAI_*`。
- Device: 无设备命令；设备 HOLD 不变。
- Tool path: 已冻结的 `harness/westlake_gap/scanner.py`、venv 和 OH SDK `llvm-readelf` 映射，精确哈希见 `INPUTS.json`。
- Artifact path: 本目录的 `OUTER-COMMAND.json`、`RESULT.json`、`SEAL.json` 与 `phases/*`；原包位于 `NANHAI_STAGING_ROOT/apk-opera-official-v1/opera-arm64.apk`，279570110 字节。
- App: Opera Browser 102.3.5206.90530，`com.opera.browser`，versionCode 1910213408。

## Status
- Label: `build_pass` 不适用；`stub`、`real_impl`、`device_verified` 均不声明。实际范围为 `static_only`。
- Label: `static_only`；主机扫描候选一次执行 rc0，待独立后审与 root 接受。`build_pass`、`device_verified` 均不声明。
- Why: 原包身份已有 root 准入；此次执行使用 root 委派的 G295 单次本地静态授权，权威静态计数尚未更新。

## Observed wall
- Classification: none
- Fact: 四阶段命令均 rc0；当前范围无事实失败墙。
- Evidence: `OUTER-COMMAND.json` 与 `phases/*/COMMAND.json`。
- First failing command: none
- Exit/status: rc0

## Hypotheses
- Candidate: none
- Cheapest falsifier: 不适用。
- Blocking: no

## Proven
- 外层原始命令 `OUTER-COMMAND.json` rc0，耗时 30.09 秒；四阶段按 ZIP、metadata、ELF、DEX 顺序各 rc0，原始 stdout/stderr 和哈希齐备。
- ZIP 7309 项 CRC 全扫，唯一 Manifest；8 DEX、19 真 ARM64 ELF；11 项结果检查全 true。APK、扫描源码、venv 与工具前后校验一致。
- `SEAL.json` 锁定 32 个输入/输出文件及哈希；`RESULT.json` SHA-256 `52969dfb5396da25df7922d692b6bad2a6135609f110922f1e78268369e1d63a`。

## Not proven
- 真正冷启动、黑盒资格、Bionic runtime、设备行为、整工具通过及权威完整静态计数增加均未证明。

## Failed
- 本次无失败阶段；未进行容器、namespace 或设备命令。

## Next evidence
- Command: 独立复算 `SEAL.json` 所列 SHA 与 `RESULT.json`、四阶段收据。
- Expected output: 文件哈希一致、四阶段 rc0、全部检查为 true。
- If it fails: 保留本次原始证据，拒绝增加权威静态计数；另立修订候选。
- 独立 reviewer 复算 `SEAL.json`、原包 SHA、四阶段命令/rc/原始输出哈希和 DEX/ELF 身份；root 再决定是否接收为完整静态 1 包，另行更新控制文档。

## Shim/stub/bypass inventory
- Item: 无；只读 APK 和扫描工具。
- Owner: 外环负责独审与最终接受。
- Why it exists: 不适用。
- Removal condition: 不适用。
- Test coverage: 单次实际四阶段扫描与前后哈希校验。
- App-specific or common: 此收据只属于该精确 Opera Browser 原包。

## Memory/skill/CI/review updates
- Memory: 不写全局记忆。
- Skill: 遵守 WestLake 主机静态证据与设备证据分离。
- CI: 未纳入 CI。
- Review checklist: 独审核对原包、脚本、工具、阶段限时、原始输出、前后哈希及不计启动/设备通过。
