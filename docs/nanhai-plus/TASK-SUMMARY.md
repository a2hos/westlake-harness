# 南海 plus 前期任务汇总

核对时间：2026-10-04T04:38:46+00:00（UTC）。当前目标是 OH7.0.0.39 / android-16.0.0_r4 / ARM64，App 内单 Bionic。目标仍为 200 个不同原版 APK 的真实冷启动，其中至少 100 个合格海外主流黑盒应用。

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
| 原版 APK 下载载荷接受 | 56 | 上游登记原包 55，加官方 Signal 补充原包 1；未计签名或启动通过 |
| APK 完整静态清点 | 41 | 共 76 个 DEX、320 个 ELF；VLC、Signal 与 Keychain 未计完整清点 |
| 真实 Bionic APK 冷启动 | 0/200 | 下载、扫描和宿主编译不计启动成功 |
| 合格海外主流黑盒启动 | 0/100 | 包下载来源或黑盒意向不能替代资格与启动证据 |

原看板“剩余 30”属于旧 86 项路线的未尝试数，不能解释为“30 个已开发完成”；扩展为 89 项后历史未尝试数为 31。历史 Musl 的 38 项源码接受保留，不迁入 Bionic 完成数。退休项也不算通过。

最新实际工程结果：G267 已终态（exec62919，terminal de0e45，rc2）。346 个精确 R4 VNDK license/NOTICE/config 文件已只读接入，原四个 license 模块报错消失；本轮实际出现 24 条未定义模块错误，涉及 Python、protobuf、sqlite、jcommander、ASM 的 9 个模块。目标编译命令仍为 0，图生成未通过。root 重哈 140 项证据及 OUT/TMP，独立审查 578 项检查通过；source/SDK 前后守卫通过，三个专属卷已清理。

20 个新增上游登记原包本轮单次 GET 下载成功（exec9205，terminal783cf7，rc0），累计上游载荷 55 个，加官方 Signal 补充包共 56 个。root 核对 100 项原始引用、原登记 SHA 与完整 ZIP CRC，并经独立审查后接受。下载不证明签名、安装、主流资格或启动。Firefox 官方 ARM64 包与原登记 SHA 不符，原拒绝记录保留。

第 5 批静态扫描实际终态为 rc2（exec22164，terminal a49d2a）：Kore、uHabits、openHAB 的 3 份原始扫描输出经独立复核与 root 单项接受，新增 4 DEX、0 ELF；Keychain 在 35 秒上限终止，DEX 输出不完整。批次汇总器写死 14 包而本次输入为 4 包，故全局批次仍失败，未改写原结果。累计 37 包、72 DEX、292 ELF。VLC、Signal、Keychain 均未计完整。签名环境准备发现固定镜像的 /usr/bin/java 不存在（rc127）；现存 JDK 尚缺官方 checksum 来源绑定，候选不可执行；该准备任务总耗时 168 秒超过 150 秒上限，保留为 PARTIAL。

精确 R4 的 jcommander、ow2-asm、sqlite 源码树及 CPython 原始 Git blob 归档已只读准入共享源码池，后者 4,990 文件、112,220,160 字节并保留 Git 路径大小写和 blob 字节。macOS 大小写不敏感检出目录以及受归档过滤影响的旧 tar 均被拒绝作为构建输入；其余原版图依赖及宿主 loader 仍需核验。这是源码身份准入，不是 G268 构建图通过。

第 6 批静态扫描实际终态 rc0（exec31205，terminal d229ed，47.049 秒）。本批 Fossify Messages、Camera、Filemanager 与 Audiobook 四份原包经 327 项独立检查和 root 接受，新增 4 DEX、28 ELF，28 次 readelf 均 rc0。前后输入守卫通过，300 秒外层监督未触发；累计 41 包、76 DEX、320 ELF。扫描没有安装或启动 APK。

AOSP16 R4 build-tools Python cohort 新增 843 项只读引用，另复用 2 项；protobuf superproject 2,818 个普通文件与 py-six 19 文件按同版身份登记。protobuf 内 jsoncpp Gitlink 仍未物化。CPython 4,990 文件在一次性 Linux 卷材料化、重算官方 Git 树并删除测试卷；首轮卷权限失败如实保留。以上均非新的 Soong 图、ARM64 Bionic 编译或设备通过。

精确 R4 SDK 17,924 项、6,254,795,690 字节已准入并在实际构建前后守卫中验证；G266 的六个 API latest 缺项报错消失，继而 G267 的四个 VNDK license 缺项报错消失。构建图整体仍失败，不能据此宣称 Bionic 编译完成。

G262 两个 OH 进程外 Musl 服务库链接成功（rc0），独立核验 ARM64 ET_DYN、SONAME 和 40 个必需导出符号；复用 968 个对象，新增编译与生成均为 0。这属于进程外库 `build_pass`，不计 App 内 Bionic、整工具或设备通过。

扫描器 38 个固定依赖已离线安装，pip check 与 16 项实际导入通过。六批累计 41 个 APK 完成静态清点，失败批次只计独立复核通过的 3 个包。没有当前目标 runtime snapshot，因此未完成 full gap scan。HelloWorld 的 Bionic 安装、冷启动、上屏、输入和正常退出仍未验收。

| 已证明 | 未证明 | 实际失败 | 下一证据 |
|---|---|---|---|
| 2 个进程外服务库 `build_pass`；宿主 soong_build；41 个 APK 静态清点 | App 内 Bionic 整工具、真实冷启动、当前 runtime gap scan | G267 缺 9 个 stock 输入模块；VLC/Signal/Keychain 清点未完成；第 5 批汇总 rc2 | 精确 R4 新依赖闭合与下一 stock 图执行；Bionic 真机 Activity 启动证据 |

自进化记录：G267、原包 v7 和静态扫描第 5 批形成 3 组实际结果后，独立目录 EVO-0009 在 84.139 秒内闭合。限定预检在执行前正确拒绝“4 包输入、14 包汇总”冲突，并通过一致 4 包样例；仅此 1 项验证改进，未全局推广或计作第 3 个工具。反思当前累计 1 组新实际结果，下一次等 3–4 组新实际结果。独立 peer 的超时记录保留。

这是核对时点的任务快照，不是整项目完成声明。逐项计数及本地不可变收据路径/SHA 保存于 [TASK-SUMMARY.json](TASK-SUMMARY.json)；该文件的证据索引不声称大型构建产物已上传。

## Boundary

- Boundary: Bionic/Musl 与 Device/Tooling 的进度证据边界。
- Android behavior: AOSP16 R4 原版 APK 需要真实 Activity 冷启动证据。
- OpenHarmony mapping: OH7.0.0.39，App 内单 Bionic，进程外服务可 Musl。
- Fix layer: 本提交仅刷新任务汇总，未修改 adapter。

## Evidence target

- What this proves: 截至核对时点的已接受数量与 G267 实际终态。
- What this does not prove: 整工具完成、安装、冷启动、上屏或设备验收。

## Environment

- Host: 当前 macOS 外环，固定 Linux x86_64 容器进行 G267 宿主构建。
- Device: 本次汇总未访问设备，沿用项目 HOLD 与白名单。
- Tool path: scripts/nanhai_plus_env.py 与候选 executor.py，精确收据见 JSON 索引。
- Artifact path: .nanhai-plus-runtime/bionic-oh7-aosp16/out/bionic-stock-bionic-target-graph-v5/accepted-host/soong_build。
- App: 当前没有 APK 冷启动接受收据。

## Status

- Label: build_pass
- Why: 仅 G262 进程外库及 G265 宿主可执行文件通过构建；G267 整体图生成失败。

## Observed wall

- Classification: observed
- Fact: G267 实际报出 24 条错误，涉及 9 个 Python/protobuf/sqlite/jcommander/ASM 未定义模块。
- Evidence: G267-REVIEW.json，SHA 见 TASK-SUMMARY.json。
- First failing command: G267 stock Soong Android.bp 分析步骤（236/236）。
- Exit/status: 外层 terminal rc2；目标编译命令 0。

## Hypotheses

- Candidate: 无新增根因假设；五源插件已实际编译，完整 libcore 已执行，完整 SDK 已核验；下一批 stock 输入待精确版本闭合。
- Cheapest falsifier: 精确 R4 stock 依赖输入核验后，新候选经原 owner ACK 与封包执行。
- Blocking: no

## Proven

- 38/89 历史 Musl 源码接受、56 个原包载荷接受、41 个完整静态清点。

## Not proven

- Bionic 整工具与 APK 冷启动；包含完整 libcore 输入的 stock 图尚未通过。

## Failed

- G267 图分析 rc2；Firefox 下载 SHA 不符；VLC/Signal/Keychain 静态清点未完成；第 5 批汇总 rc2。

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
