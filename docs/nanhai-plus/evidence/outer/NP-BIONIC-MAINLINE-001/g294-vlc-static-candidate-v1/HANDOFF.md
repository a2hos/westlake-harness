# G294 VLC 3.7.1 静态清点候选

## Boundary
- Boundary: Package 与 Tooling；只扫描已接收的原版 APK，不改桥接实现。
- Android behavior: 原版 `org.videolan.vlc` APK 应保留准确包名、签名、DEX 和 ARM64 原生库字节。
- OpenHarmony mapping: 本候选不映射 OH 服务；后续 App 单 Bionic 运行另行验证。
- Fix layer: 主机证据层，ZIP、metadata、ELF、DEX 四阶段库存。

## Evidence target
- What this proves: 候选输入与上游 F-Droid 索引及已接受原包的 SHA、大小和 ABI 一致；冻结脚本可供独立审查。放行后才可证明四阶段主机静态清点。
- What this does not prove: 不证明安装、真正冷启动、上屏、输入、Bionic 运行、设备通过或黑盒资格。

## Environment
- Host: 当前 Mac 原生宿主，使用 `local_env.md` 注入的 `NANHAI_*` 环境；不使用容器或 namespace。
- Device: 无设备命令，当前设备规则与 HOLD 不变。
- Tool path: `NANHAI_PROJECT_ROOT/harness/westlake_gap/scanner.py` 及已核验的 OH SDK `llvm-readelf` 映射。
- Artifact path: `PREPARE.json` 锁定本目录 `INPUTS.json`、`common.py`、`scan_phase.py` 和 `run.py`；原 APK 位于 `NANHAI_STAGING_ROOT/apk-stock-intake-v2/org.videolan.vlc/body.raw`。
- App: F-Droid VLC 3.7.1，`org.videolan.vlc`，versionCode 13070106，ARM64，47,990,842 字节，SHA-256 `355ff246a0348c094a256926ea31cbec92701a2faca3d41d49170798c550ee3b`。

## Status
- Label: static_only；`build_pass` 未声明，本候选未执行扫描。
- Why: 缺独立 reviewer 与外环 `ROOT-RELEASE.json`；无门时执行器实际 rc=2，未创建 `phases`。

## Proven
- 原包与 `benchmark/2026-09-23-corpus2-blind/downloads.lock.json` 和 `apk-stock-intake-v2/root-intake-v1/ROOT-ACCEPTANCE.json` 一致。
- 预检确认当前扫描源码、venv 清单和 `llvm-readelf` 的冻结 SHA 一致；脚本语法检查 rc=0。

## Not proven
- 四阶段完整扫描、独立复核、外环接收、资格计数与启动均未完成；权威原包 81、完整静态 77 不变。

## Failed
- 历史批次 VLC 150 秒超时，只留下局部 ELF/DEX 资料，不能计完整静态。
- 当前候选无双门调用返回 `INDEPENDENT_REVIEW_AND_ROOT_RELEASE_REQUIRED`，符合预期拒绝。

## Next evidence
- Command: 独立 reviewer 核对冻结 SHA 并写 `peer-review-v1/REVIEW.json`；外环另写 `ROOT-RELEASE.json` 后，运行 `python3 -B scripts/nanhai_plus_env.py --run python3 -B docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g294-vlc-static-candidate-v1/run.py --execute`。
- Expected output: ZIP 2618 项 CRC 全过、唯一 Manifest、6 DEX、4 真 ARM64 ELF；四阶段 rc=0，前后输入哈希一致。
- If it fails: 保留每阶段原始 stdout/stderr、命令和失败收据；不重试旧包，不更新计数，按第一个失败阶段修订新候选。

## Shim/stub/bypass inventory
- Item: 无；此候选只读取 APK 和扫描工具。
- Owner: 外环负责放行与最终验收。
- Why it exists: 不适用；没有新增 shim、stub 或 bypass。
- Removal condition: 不适用。
- Test coverage: 冻结输入预检及无双门拒绝；实际四阶段尚未执行。
- App-specific or common: VLC 这一精确原包的清点候选。

## Memory/skill/CI/review updates
- Memory: 不写全局记忆；候选证据留本目录。
- Skill: 遵守 WestLake 主机静态证据与设备证据分离。
- CI: 本候选尚未纳入 CI。
- Review checklist: 独立 reviewer 核对 APK/锁、源码与工具、脚本只读边界、阶段限时、无容器和无设备操作；外环再核对实际终端收据。
