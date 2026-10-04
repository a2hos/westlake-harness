# 南海 plus 前期任务汇总

核对时间：2026-10-04T02:33:18.596980+00:00（UTC）。当前目标是 OH7.0.0.39 / android-16.0.0_r4 / ARM64，App 内单 Bionic。目标仍为 200 个不同原版 APK 的真实冷启动，其中至少 100 个合格海外主流黑盒应用。

**如果“开发完成”指源码复现，历史 Musl 路线已接受 38/89；如果指当前 Bionic 架构下整工具完成，当前是 0/89。** 两个数量不能合并。

| 范围 | 已核实数量 | 含义 |
|---|---:|---|
| 当前 Bionic 整工具完成 | 0/89 | 构建、功能与适用验收均完成才计入 |
| 当前 Bionic 构建接受 / 设备验证 | 0 / 0 | 外部服务对象不能计入 App 内 Bionic 工具通过 |
| 当前工具架构归属复核 | 88/89 | 32 重建、51 原生替代计划、5 条件保留、1 待判定；方案不等于实现 |
| 历史 Musl 源码复现接受 | 38/89 | 原 86 项中 36 项，加新增 3 项中的 2 项 |
| 历史 Musl 已尝试 / 未尝试 | 58 / 31 | 原 86 项已尝试 56，加新增项已尝试 2 |
| 历史 Musl 限定原生工具设备通过 | 12 | 限定检查范围，不代表整工具或 APK 跑通 |
| 新增自进化工具 | 2 项限定小试通过 | APK 清点、stock 模块前沿报告；未全面推广，不增加原 89 项通过数 |
| 原版 APK 下载载荷接受 | 21 | 前两批 11 个，加第三批已接受 10 个；另 2 个完整下载待外环验收 |
| APK 完整静态清点 | 10 | 共 18 个 DEX、124 个 ELF；VLC 超时，未计完整清点 |
| 真实 Bionic APK 冷启动 | 0/200 | 下载、扫描和宿主编译不计启动成功 |
| 合格海外主流黑盒启动 | 0/100 | 包下载来源或黑盒意向不能替代资格与启动证据 |

原看板“剩余 30”属于旧 86 项路线的未尝试数，不能解释为“30 个已开发完成”；扩展为 89 项后历史未尝试数为 31。历史 Musl 的 38 项源码接受保留，不迁入 Bionic 完成数。退休项也不算通过。

最新实际工程结果：G263 已终止（rc2）。精确 R4 Ninja 已真实执行，10 个宿主工具 loader 核验通过；Soong bootstrap 完成 233/234 步，生成 Linux x86_64 的 `soong_build`。最后 Android.bp 分析失败：`ide_query_cc_analyzer_defaults` 依赖未定义的 `llvm-build-host-tools-defaults`。ARM64 Bionic 目标编译命令仍为 0。OUT/TMP 导出通过，FIFO 仅保留元数据，专属容器和卷已清理。

该缺项相关的精确 R4 根 Android.bp 和四文件 Soong 插件子目录已核验准入，共 5 个源文件。Graph v6 候选独审通过，但尚未执行；需要原 owner 新 ACK 和外环封包。源码准入不代表新插件已编译或缺项已解决。

G262 两个 OH 进程外 Musl 服务库链接成功（rc0），独立核验 ARM64 ET_DYN、SONAME 和 40 个必需导出符号；复用 968 个对象，新增编译与生成均为 0。这属于进程外库 `build_pass`，不计 App 内 Bionic、整工具或设备通过。

扫描器 38 个固定依赖已离线安装，pip check 与 16 项实际导入通过。两批累计 10 个 APK 完成静态清点；VLC 在 150 秒上限超时，未重试、未计完整。没有当前目标 runtime snapshot，因此未完成 full gap scan。HelloWorld 的 Bionic 安装、冷启动、上屏、输入和正常退出仍未验收。

| 已证明 | 未证明 | 实际失败 | 下一证据 |
|---|---|---|---|
| 2 个进程外服务库 `build_pass`；宿主 soong_build；10 个 APK 静态清点 | App 内 Bionic 整工具、真实冷启动、当前 runtime gap scan | G263 缺 LLVM defaults；VLC 清点超时 | Graph v6 原 owner ACK 后实际执行；Bionic 真机 Activity 启动证据 |

自进化记录：EVO-0005 验证了一项本地 curl 参数预检改进，不增加工具完成数。该轮耗时 188.9 秒，超过 120 秒上限，已记录节奏不合规。后续保持每 3–4 组实际结果反思一次，外环监督截止时间。

这是核对时点的任务快照，不是整项目完成声明。逐项计数及本地不可变收据路径/SHA 保存于 [TASK-SUMMARY.json](TASK-SUMMARY.json)；该文件的证据索引不声称大型构建产物已上传。

## Boundary

- Boundary: Bionic/Musl 与 Device/Tooling 的进度证据边界。
- Android behavior: AOSP16 R4 原版 APK 需要真实 Activity 冷启动证据。
- OpenHarmony mapping: OH7.0.0.39，App 内单 Bionic，进程外服务可 Musl。
- Fix layer: 本提交仅刷新任务汇总，未修改 adapter。

## Evidence target

- What this proves: 截至核对时点的已接受数量与 G263 实际终态。
- What this does not prove: 整工具完成、安装、冷启动、上屏或设备验收。

## Environment

- Host: 当前 macOS 外环，固定 Linux x86_64 容器进行 G263 宿主构建。
- Device: 本次汇总未访问设备，沿用项目 HOLD 与白名单。
- Tool path: scripts/nanhai_plus_env.py 与候选 executor.py，精确收据见 JSON 索引。
- Artifact path: .nanhai-plus-runtime/bionic-oh7-aosp16/out/bionic-stock-bionic-target-graph-v5/accepted-host/soong_build。
- App: 当前没有 APK 冷启动接受收据。

## Status

- Label: build_pass
- Why: 仅 G262 进程外库及 G263 宿主可执行文件通过构建；G263 整体图生成失败。

## Observed wall

- Classification: observed
- Fact: ide_query_cc_analyzer_defaults 依赖未定义的 llvm-build-host-tools-defaults。
- Evidence: G263-REVIEW.json，SHA 见 TASK-SUMMARY.json。
- First failing command: G263 stock Soong Android.bp 分析步骤（234/234）。
- Exit/status: 外层 terminal rc2；目标编译命令 0。

## Hypotheses

- Candidate: 无新增根因假设；五源补齐的效果仍待实际执行。
- Cheapest falsifier: Graph v6 经原 owner 新 ACK 与封包后实际执行。
- Blocking: no

## Proven

- 38/89 历史 Musl 源码接受、21 个原包下载接受、10 个完整静态清点。

## Not proven

- Bionic 整工具与 APK 冷启动；补齐插件后的 stock 图通过。

## Failed

- G263 图分析 rc2；VLC 静态清点超时。

## Next evidence

- Command: 原 owner 接受新候选后，通过 NANHAI 环境入口执行新封包。
- Expected output: 记录真实图分析结果及首个失败，成功时继续目标编译门。
- If it fails: 保留原始收据，按精确版本定位下一缺项，不算成功。

## Shim/stub/bypass inventory

- Item: 本次汇总没有新增 shim、stub 或 bypass。
- Owner: 外环。
- Removal condition: 不适用。
- Test coverage: 汇总证据 SHA 核验与 Markdown/JSON 一致性检查。

## Memory/skill/CI/review updates

- Memory: 未写入记忆。
- Skill: 使用 westlake-engineering-discipline 核验结果范围。
- CI: 执行 westlake_gate 与 git diff --check；未改变 CI。
- Review checklist: 历史 Musl、当前 Bionic、下载、静态清点和设备验收独立计数。
