# 南海 plus 前期任务汇总

核对时间：2026-10-04T03:02:24.734932+00:00（UTC）。当前目标是 OH7.0.0.39 / android-16.0.0_r4 / ARM64，App 内单 Bionic。目标仍为 200 个不同原版 APK 的真实冷启动，其中至少 100 个合格海外主流黑盒应用。

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
| 原版 APK 下载载荷接受 | 35 | 五批累计接受 3 + 8 + 10 + 2 + 12 个完整原包载荷 |
| APK 完整静态清点 | 20 | 共 38 个 DEX、209 个 ELF；VLC 超时，未计完整清点 |
| 真实 Bionic APK 冷启动 | 0/200 | 下载、扫描和宿主编译不计启动成功 |
| 合格海外主流黑盒启动 | 0/100 | 包下载来源或黑盒意向不能替代资格与启动证据 |

原看板“剩余 30”属于旧 86 项路线的未尝试数，不能解释为“30 个已开发完成”；扩展为 89 项后历史未尝试数为 31。历史 Musl 的 38 项源码接受保留，不迁入 Bionic 完成数。退休项也不算通过。

最新实际工程结果：G265 已终止（exec31374，terminal e9ac25，rc2）。完整精确 R4 libcore 的 8,280 个文件已接入，宿主 bootstrap 完成 235/236 步，最后 Android.bp 分析在 `libcore/JavaLibrary.bp:1223:1` 报出六个未定义模块：`art.api.combined.{public,system,module-lib}.latest` 和 `art-removed.api.combined.{public,system,module-lib}.latest`。ARM64 Bionic 目标编译命令仍为 0；源码前后守卫相等，OUT/TMP 导出哈希通过，专属卷全部清理。此前 G264 的两个 Java stubs 缺项不再是本轮首个失败。

新一批 12 个原包实际下载 rc0，共 247,686,199 字节，独审 269 项通过；外环重新核验 72 个原始引用、原包 SHA/大小及 ZIP 全成员 CRC 后接受，累计下载 35 个。接受范围为原始载荷身份，尚未证明签名、split 完整性、主流资格或安装启动。第三批 10 个 APK 静态扫描实际 rc0（261 秒），20 DEX / 85 ELF 已计入完整静态清点，累计 20 包。另已整理 20 个入口 Activity 候选，属于启动准备。

G262 两个 OH 进程外 Musl 服务库链接成功（rc0），独立核验 ARM64 ET_DYN、SONAME 和 40 个必需导出符号；复用 968 个对象，新增编译与生成均为 0。这属于进程外库 `build_pass`，不计 App 内 Bionic、整工具或设备通过。

扫描器 38 个固定依赖已离线安装，pip check 与 16 项实际导入通过。三批累计 20 个 APK 完成静态清点；VLC 在 150 秒上限超时，未重试、未计完整。没有当前目标 runtime snapshot，因此未完成 full gap scan。HelloWorld 的 Bionic 安装、冷启动、上屏、输入和正常退出仍未验收。

| 已证明 | 未证明 | 实际失败 | 下一证据 |
|---|---|---|---|
| 2 个进程外服务库 `build_pass`；宿主 soong_build；20 个 APK 静态清点 | App 内 Bionic 整工具、真实冷启动、当前 runtime gap scan | G265 缺六个 ART API latest 模块；VLC 清点超时 | 六个实际缺失模块的精确 R4 输入核验及新 stock 图执行；Bionic 真机 Activity 启动证据 |

自进化记录：EVO-0005 的本地 curl 方法验证保留，其耗时超限记录保留。完成 4 组实际结果后，EVO-0006 尝试证据格式检查；截至外环截止时只有 START 记录，没有可核验改进，已中断并闭合，不算新工具或推广。后续继续每 3–4 组实际结果一次，最多 120 秒、一项改进。

这是核对时点的任务快照，不是整项目完成声明。逐项计数及本地不可变收据路径/SHA 保存于 [TASK-SUMMARY.json](TASK-SUMMARY.json)；该文件的证据索引不声称大型构建产物已上传。

## Boundary

- Boundary: Bionic/Musl 与 Device/Tooling 的进度证据边界。
- Android behavior: AOSP16 R4 原版 APK 需要真实 Activity 冷启动证据。
- OpenHarmony mapping: OH7.0.0.39，App 内单 Bionic，进程外服务可 Musl。
- Fix layer: 本提交仅刷新任务汇总，未修改 adapter。

## Evidence target

- What this proves: 截至核对时点的已接受数量与 G265 实际终态。
- What this does not prove: 整工具完成、安装、冷启动、上屏或设备验收。

## Environment

- Host: 当前 macOS 外环，固定 Linux x86_64 容器进行 G265 宿主构建。
- Device: 本次汇总未访问设备，沿用项目 HOLD 与白名单。
- Tool path: scripts/nanhai_plus_env.py 与候选 executor.py，精确收据见 JSON 索引。
- Artifact path: .nanhai-plus-runtime/bionic-oh7-aosp16/out/bionic-stock-bionic-target-graph-v5/accepted-host/soong_build。
- App: 当前没有 APK 冷启动接受收据。

## Status

- Label: build_pass
- Why: 仅 G262 进程外库及 G265 宿主可执行文件通过构建；G265 整体图生成失败。

## Observed wall

- Classification: observed
- Fact: libcore/JavaLibrary.bp:1223:1 的六个 ART API latest 模块未定义。
- Evidence: G265-REVIEW.json，SHA 见 TASK-SUMMARY.json。
- First failing command: G265 stock Soong Android.bp 分析步骤（236/236）。
- Exit/status: 外层 terminal rc2；目标编译命令 0。

## Hypotheses

- Candidate: 无新增根因假设；五源插件已实际编译，完整 libcore 已执行，六个 API 模块的输入效果待后续新封包验证。
- Cheapest falsifier: 精确 R4 API 模块输入核验后，新候选经原 owner ACK 与封包执行。
- Blocking: no

## Proven

- 38/89 历史 Musl 源码接受、35 个原包下载接受、20 个完整静态清点。

## Not proven

- Bionic 整工具与 APK 冷启动；包含完整 libcore 输入的 stock 图尚未通过。

## Failed

- G265 图分析 rc2；VLC 静态清点超时。

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
