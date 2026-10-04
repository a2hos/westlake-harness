# 南海 plus 前期任务汇总

核对时间：2026-10-04T09:31:19.675635+00:00（UTC）。当前目标是 OH7.0.0.39 / android-16.0.0_r4 / ARM64，App 内单 Bionic。目标仍为 200 个不同原版 APK 的真实冷启动，其中至少 100 个合格海外主流黑盒应用。

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
| 原版 APK 下载载荷接受 | 77 | 上游登记原包 73，加 Signal、WhatsApp、Vivaldi 与 Proton Meet 官方渠道补充原包各 1；均未计启动 |
| APK 完整静态清点 | 73 | 共 147 个 DEX、522 个真正 ELF；VLC、Signal、Keychain 仍未计完整清点 |
| 真实 Bionic APK 冷启动 | 0/200 | 下载、扫描和宿主编译不计启动成功 |
| 合格海外主流黑盒启动 | 0/100 | 包下载来源或黑盒意向不能替代资格与启动证据 |

原看板“剩余 30”属于旧 86 项路线的未尝试数，不能解释为“30 个已开发完成”；扩展为 89 项后历史未尝试数为 31。历史 Musl 的 38 项源码接受保留，不迁入 Bionic 完成数。退休项也不算通过。

EVO18 在 G274 终态、Proton Meet 原包/静态两组、G275 终态共四组实际结果后闭合：只读小试将 181 条模块类型报错按注册来源聚类，提出下一轮图前精确来源闭合检查。仅限候选，未推广、未增加工具/启动数；反思计数归零。

G276 v20 42 根图候选已通过静态检查与独审/root 限定准入：198,046 条精确路径、3 条 stock 视图链接目标；原 owner 新 ACK、封包和实际 Linux 图尚未发生。

G276 的 `system/tools/hidl` 与 `system/apex` 两棵完整官方 R4 仓（共 997 项）已通过源码身份独审和外环准入。两处跨仓符号链接还要在 stock 路径核验；42 根 Linux 视图、Soong 图和目标构建均未验收。

最新构建图实际结果：G275（exec23044，chunk4e7b58，rc2）已由原 owner 新 ACK、独审和外环复核。40 棵源码根只读挂载，Soong bootstrap 250/250，但 target-graph 返回 rc1，图生成与产品配置验收均未通过；182 条报错集中为 HIDL 模块类型 178 条、APEX 模块类型 3 条、缺少 system/apex/Android.bp 1 条。G274 两个未定义模块不再报错。目标编译 0、设备命令 0、Bionic 整工具仍 0/89；G275 封包已用，禁止重放。下一步准入精确 R4 的 system/tools/hidl 与 system/apex 完整源码根，再独审新图。

最新构建图实际结果：G273 已终态（exec42573，terminal 37e6c6，rc2），经原 owner 新 ACK/root 封包、独审/root 接受。Soong 宿主引导 240/240，G272 的五种缺项均消失；本轮新报 12 种未定义模块、18 条诊断，首个是 `documentsui_defaults`（CarDocumentsUI）。源码/SDK 前后守卫一致，OUT/TMP 哈希核对与清理命令收据通过；目标编译命令 0。G274 九个精确 R4 仓获源码身份准入（85,499 跟踪项、1,875,247,905 字节）；只读虚拟路径侦察发现 13 链中 12 个可由已准入根解析、1 个原版即悬空；与旧视图 4 个路径完全同字节、无冲突。G274/v18 的输入候选经独审与 root 仅获输入准入；v18 materializer 扩展的 38 根静态检查已通过并独审/root 限定接受；首版完整 one-shot 执行器独审被阻断：继承的结果校验器只允许旧 29 仓，九个新增仓会被误拒；v2 正修订精确允许集，真实 Linux 挂载与 stock 图均未执行，尚无新图 ACK/执行。G273 旧包禁止重放。

最新构建图实际结果：G272 已终态（exec19714，terminal 1b5375，rc2），原 owner 新 ACK、root 封包与独审均成立。Soong 宿主引导 240/240，AIDL/XSDC 插件参与，前轮六处未识别类型不再出现；新的最早失败为 `tradefed_errorprone_defaults` 未定义，另有 Car、simpleperf、Lint、Connectivity 四种缺项，共六条诊断。源码/SDK 前后守卫一致，OUT/TMP 归档哈希通过，清理命令收据通过；目标编译命令 0。G273 精确 R4 源码定位中，G272 禁止重放。

最新构建图实际结果：G271 已终态（exec87818，terminal b5c83a，rc2）。原 owner 对 17 项输入的 ACK、root 封包及独立预审成立；宿主 Soong 236/236 后原版 CTS 分析出现 5 处 `aidl_interface` 和 1 处 `xsd_config` 未识别类型，首处为 `cts/tests/tests/hardware/Android.bp:19:1`。G270 的 5 个缺模块错误未作为本轮首错出现。源码/SDK 前后守卫一致，OUT/TMP 哈希和资源清理有独立复核；目标编译命令仍为 0。精确 R4 `system/tools/aidl`（2048 文件、2 链接）与 `system/tools/xsdc`（137 文件）已按官方 Git 身份准入为只读源码树，stock 路径与 AIDL 两个链接目标尚未核验可用，G272 候选未封、未执行。

G273 的五棵精确 R4 源码树（16,285 项）及额外 `system/core` 原版树（1,915 项）已分别通过独审与外环**源码身份准入**；`system/core/.clang-format-2` 的 stock 链接链和 G273 图仍未放行。A3 两次实际取包均整体 rc2，仅 LocalSend、Linphone 两个完整原包经独审与外环接受，新增 105,587,196 字节；Home Assistant Minimal、Nextcloud Notes 两轮 rc28 partial 不计。当时累计 71 原包、65 完整静态，启动数不变。

A3 两包隔离静态扫描实际 exec65299/chunk9a91d5/rc0，独审和 root 接受后新增 2 DEX、19 ARM64 ELF；LocalSend 与 Linphone 分别 1DEX/5ELF 和 1DEX/14ELF，19 次 readelf 均 rc0，源码/原包/工具/环境前后守卫一致。累计 **65 份完整静态清单、122 DEX、457 ELF**；它们仍未启动。

A4 又实际获取 4 个上游登记的小型原包（Files、Libre Contacts Backup、Stopwatch、aka Alarm）：exec59955/chunk857dd6/rc0，合计 2,286,257 字节；经独审与外环接受后，当前累计 **75 原包、65 完整静态**。签名、黑盒资格和启动均未由取件证明，四包的静态清点另行执行。

batch12 v3 修复后，Seal 与 Briar 两份完整静态清点经独审及 root 接受，新增 3 DEX、14 真 ELF；Seal 内 3 个 ZIP 格式 `.so` 另列，不能误计 ELF。A4 v2 四份清点独审及 root 接受，新增 4 DEX、4 ELF；v1 外层 rc2 和 v2 输入 scope 沿袭文案保留为模板修订事项。当时累计 **75 原包、71 份完整静态、129 DEX、475 真 ELF**。随后 Vivaldi 官方固定版本原包经独审及 root 仅作载荷接受，当时 **76 原包、72 完整静态**；Vivaldi 的 5,097 个 ZIP 成员静态检查经独审及 root 接受，新增 2 DEX、2 真 ARM64 ELF；黑盒资格及冷启动未通过，冷启动仍为 0。

历史构建图结果：G270 已终态（exec87143，terminal ab03cc，rc2）。精确 R4 JUnit/Hamcrest 接入后，`junit` 缺项消失；原版 Soong 图分析同时报 5 个未定义模块：`doclava`、`jsilver`、`compatibility-host-util`、`cts-tradefed`、`vts-tradefed`。源与 SDK 前后守卫一致，OUT/TMP 出口哈希核对通过，目标编译命令仍为 0。五棵精确 R4 完整源码树（含 CTS）已通过官方原始元数据、完整树和 ART 单文件外链审查并登记为只读入口；G271/v15 候选经 570 项独立检查和 root 审查，后由原 octos-inner 新 ACK 与 root 封包执行为 G271；源码准入及 ACK 均不代表图闭合。G270 不重放。

上一轮 G269 终态 rc2，唯一缺项 `junit`；前轮 Abseil 墙已消失。该历史失败保留。

历史构建图实际结果：G268 已终态（exec56670，terminal85f3ce，rc2）。原版 Soong 236/236 后首错为 `external/protobuf/Android.bp:128:1` 的 `absl_notls_defaults` 未定义，309 行同类错误；前轮九模块墙已消失。源与 SDK 前后守卫通过，SDK 17,924 项 / 6.25 GB，专属容器与卷已清理；ARM64 目标编译命令仍为 0。下一步仅按精确 AOSP16 R4 补 Abseil 模块输入，新包须新 ACK，G268 不重放。

历史上一轮工程结果：G267 已终态（exec62919，terminal de0e45，rc2）。346 个精确 R4 VNDK license/NOTICE/config 文件已只读接入，原四个 license 模块报错消失；G267 该轮实际出现 24 条未定义模块错误，涉及 Python、protobuf、sqlite、jcommander、ASM 的 9 个模块。目标编译命令仍为 0，图生成未通过。root 重哈 140 项证据及 OUT/TMP，独立审查 578 项检查通过；source/SDK 前后守卫通过，三个专属卷已清理。

20 个新增上游登记原包本轮单次 GET 下载成功（exec9205，terminal783cf7，rc0），累计上游载荷 55 个，加官方 Signal 补充包共 56 个。root 核对 100 项原始引用、原登记 SHA 与完整 ZIP CRC，并经独立审查后接受。下载不证明签名、安装、主流资格或启动。Firefox 官方 ARM64 包与原登记 SHA 不符，原拒绝记录保留。

第 5 批静态扫描实际终态为 rc2（exec22164，terminal a49d2a）：Kore、uHabits、openHAB 的 3 份原始扫描输出经独立复核与 root 单项接受，新增 4 DEX、0 ELF；Keychain 在 35 秒上限终止，DEX 输出不完整。批次汇总器写死 14 包而本次输入为 4 包，故全局批次仍失败，未改写原结果。累计 37 包、72 DEX、292 ELF。VLC、Signal、Keychain 均未计完整。签名环境准备发现固定镜像的 /usr/bin/java 不存在（rc127）；现存 JDK 尚缺官方 checksum 来源绑定，候选不可执行；该准备任务总耗时 168 秒超过 150 秒上限，保留为 PARTIAL。

精确 R4 的 jcommander、ow2-asm、sqlite 源码树及 CPython 原始 Git blob 归档已只读准入共享源码池，后者 4,990 文件、112,220,160 字节并保留 Git 路径大小写和 blob 字节。macOS 大小写不敏感检出目录以及受归档过滤影响的旧 tar 均被拒绝作为构建输入；其余原版图依赖及宿主 loader 仍需核验。这是源码身份准入，不是 G268 构建图通过。

第 6 批静态扫描实际终态 rc0（exec31205，terminal d229ed，47.049 秒）。本批 Fossify Messages、Camera、Filemanager 与 Audiobook 四份原包经 327 项独立检查和 root 接受，新增 4 DEX、28 ELF，28 次 readelf 均 rc0。前后输入守卫通过，300 秒外层监督未触发；累计 41 包、76 DEX、320 ELF。扫描没有安装或启动 APK。

第 7/8 批分别以 rc0 终态执行（exec11967/terminal97d58f，exec57454/terminal1ae3c8），各 4 份原包经独立复核与 root 接受；合计新增 21 DEX、52 ELF，累计 **49 包、97 DEX、372 ELF**。第 8 批 OpenTracks 原始版本字符串 `v4.28.3irreproducible` 原样保留。仅静态清点，未启动。第 9 批另以 rc0 终态执行（exec78401，terminal5b27d4），F-Droid、Just Player、Unciv 与 AdAway 4 份原包经 997 项独立检查和 root 接受，新增 12 DEX、38 ELF，累计 **53 包、109 DEX、410 ELF**；外层 300 秒看门狗仅有父进程观察，无独立持久化外层转录。第 10 批新四原包实际 exec7036/terminal99685a/rc0，在完整外层监督 38.836 秒内完成，273 项独立复核与 root 接受新增 4 DEX、20 ELF，累计 **57 包、113 DEX、430 ELF**。

第 8 次原包取件（v8）实际 exec64981/terminal270431/rc0，四份此前未取的 F-Droid 精确锁定原包经 257 项独立检查和 root 接受，共 26,489,238 字节，全部 ZIP CRC 通过；累计 **61**。下载并未证明签名、Manifest 语义、分包完整性或启动。

第 9 次原包取件（v9）实际 terminal c63157/rc0，Noice、Retro Music、FitoTrack、WiFiAnalyzer 四份精确锁定原包经 279 项独立检查和 root 接受，累计 **65**。第 11 批四份新原包静态扫描实际 exec84077/terminal f1152e/rc0，在外层 300 秒看门狗内完成，245 项独立检查和 root 接受新增 4 DEX、8 ELF，累计 **61 包、117 DEX、438 ELF**。Noice 仅完成静态清点，未验证启动。

A2 取件四份精确登记原包（GPS Cockpit、AndStatus、Seal、Briar）实际外层 rc0、54.17 秒，104,901,036 字节，独立 54 项复核及 root 接受后累计 **69** 原包；未证执行期间独立源码 postguard。batch12 首候选交接工程 gate rc1 被保留，v2 修订候选经 96 项独审和 gate rc0 后一次执行：外层 exec22556/terminal b8a122/rc2、100.58 秒、未触发 300 秒看门狗。仅 GPS Cockpit 与 AndStatus 两份完整静态结果逐包接受，新增 3 DEX、0 ELF，累计 **63 包、120 DEX、438 ELF**。Seal 的 `libaria2c.zip.so` 实为 ZIP 头，扫描器 ELF 断言失败；Briar 90 秒单包超时，均不计完整。Briar 遗留的派生临时 SO 已在终态独审后按 SHA 收据删除。

WhatsApp 官网页面标记 `2.26.32.84` 的原始下载 148,660,262 字节、15,156 ZIP 成员 CRC 通过，经 64 项独立复核后仅作为官方渠道新增载荷接受；历史登记 `2.26.37.73` XAPK 不替换。当时原包累计 **57**。随后只读实际检查两条工具命令均 rc0，apksigner 报告 v1/v2/v3/v3.1 验证通过；包内 Manifest 为 `com.whatsapp` / `2.26.39.71`，与网页标签不一致，旧整体收据 rc2 保留。原始文本解析补识别两个 SDK 区间证书，未重跑工具；官方发布者绑定、黑盒资格及启动未验收。

AOSP16 R4 build-tools Python cohort 新增 843 项只读引用，另复用 2 项；protobuf superproject 2,818 个普通文件与 py-six 19 文件按同版身份登记。protobuf 内 jsoncpp Gitlink 仍未物化。CPython 4,990 文件在一次性 Linux 卷材料化、重算官方 Git 树并删除测试卷；首轮卷权限失败如实保留。以上均非新的 Soong 图、ARM64 Bionic 编译或设备通过。

精确 R4 SDK 17,924 项、6,254,795,690 字节已准入并在实际构建前后守卫中验证；G266 的六个 API latest 缺项报错消失，继而 G267 的四个 VNDK license 缺项报错消失。构建图整体仍失败，不能据此宣称 Bionic 编译完成。

G262 两个 OH 进程外 Musl 服务库链接成功（rc0），独立核验 ARM64 ET_DYN、SONAME 和 40 个必需导出符号；复用 968 个对象，新增编译与生成均为 0。这属于进程外库 `build_pass`，不计 App 内 Bionic、整工具或设备通过。

扫描器 38 个固定依赖已离线安装，pip check 与 16 项实际导入通过。此前十二批累计 63 个 APK 完成静态清点，A3 又接受 2 个，失败批次合计只计逐包独立复核通过的 5 个包。没有当前目标 runtime snapshot，因此未完成 full gap scan。HelloWorld 的 Bionic 安装、冷启动、上屏、输入和正常退出仍未验收。

| 已证明 | 未证明 | 实际失败 | 下一证据 |
|---|---|---|---|
| 2 个进程外服务库 `build_pass`；宿主 soong_build；72 个 APK 静态清点 | App 内 Bionic 整工具、真实冷启动、当前 runtime gap scan | G273 有 18 处未定义模块依赖；batch12 整批 rc2；WhatsApp 网页与包内版本不一致 | 精确 R4 十二种缺项定义与下一图候选；Bionic 真机 Activity 启动证据 |

自进化 EVO-0010 已在第 6/7/8 批静态清点及 WhatsApp 原包四组结果后，90.403 秒内闭合。验证 1 项调用时绑定工具 SHA、argv 与显式环境的局部无网络试验，10 个负例拒绝；未推广、未改变 G268，也未增加原 89 项工具通过数。此前 3 组实际结果（G268、WhatsApp 只读命令、G269）触发 EVO-0011；它已在 120 秒硬上限关闭，新增验证改进 0、推广 0；随后第 9 批、G270 和第 8 次原包取件构成新三组，EVO-0012 在 55.93 秒内验证一个限定身份链校验器：真实收据 rc0、篡改哈希负例 rc2。未推广、未测节省时间。第 10 批静态扫描、原包 v9 取件、第 11 批静态扫描形成随后三组实际结果，触发 EVO-0013 专职 peer，82.9 秒内闭合一项限定试点：对 10 个 Tier-B 黑盒候选做包名、历史工件 SHA 与有证版本的严格联接，v8/v9 和 WhatsApp 试点输入中 0 个历史工件精确命中；错误版本/SHA 负例未误判，WhatsApp 新版单列。该试点未覆盖当时全部 65 原包，未推广，不增加黑盒资格或启动数。随后 G271、A2 原包与 batch12 三组实际结果触发 EVO-0014：只读分流试点将 Seal 的非 ELF `.zip.so` 与 Briar 超时保留为两种未决类型，四个负例均拒绝；未推广，反思计数归零。

EVO-0015 在 G272 图结果、A3 原包和 A3 静态三组真实结果后闭合一项只读局部试验：用实际 stock bind 命令与精确 R4 源码中的 `name:` 定义定位五种缺项，5/5 为未挂载候选；已挂载模块和假名负例未误报。只辅助下一轮来源准备，不能替代 Soong 图/运行验收，未推广或增加 89 项通过数。

历史自进化记录：G267、原包 v7 和静态扫描第 5 批形成 3 组实际结果后，独立目录 EVO-0009 在 84.139 秒内闭合。限定预检在执行前正确拒绝“4 包输入、14 包汇总”冲突，并通过一致 4 包样例；仅此 1 项验证改进，未全局推广或计作第 3 个工具。该轮四组实际结果已经闭合，不重复反思。独立 peer 的超时记录保留。

G273 图、A4 原包、batch12 v3 修复和 A4 v2 清点构成新四组实际结果，EVO-0016 专职 peer 闭合一项只读 ELF 成员复用身份键试验：14 条已接受成员收据及 11 项变更失效控制通过；未实际缓存复用、未测节省时间、未推广，不增加 89 项或启动通过数。

G274 输入/静态扩展门、Vivaldi 原包、Vivaldi 静态和 G274 完整执行器独审阻断构成新四组实际结果，EVO-0017 已闭合一项只读 oracle 身份重检小试：对最终 v2 候选注入已有缓存哨兵后仍重新核对候选身份并拒绝漂移。最初瞬态缺陷无旧源码 SHA，按证据限制单列；未推广，不计工具或启动。

这是核对时点的任务快照，不是整项目完成声明。逐项计数及本地不可变收据路径/SHA 保存于 [TASK-SUMMARY.json](TASK-SUMMARY.json)；该文件的证据索引不声称大型构建产物已上传。

G275 已从官方 `android-16.0.0_r4` 补齐并独立复核 `kernel/configs` 与 `system/sepolicy` 两棵完整仓，共 4,587 个受控条目；共享索引和项目内只读软链接已登记。两条 stock 根与既有 38 根无路径冲突，外环仅准入源码身份和静态输入视图；Linux 挂载、图构建、目标编译和原 owner 新 ACK 仍未发生。详见 TASK-SUMMARY.json 的 `g275_source_view_admission`。

Proton Meet 官网 APK（`proton.android.meet` 1.2.2，262,604,360 字节）经独立复验签名/ZIP/版本与 root 仅作精确原包接受，累计 **77 原包、73 完整静态**；Proton Meet 静态独审/root 接受新增 16 DEX、45 真 ELF（15 ARM64），主流黑盒资格与冷启动仍为 0。G275/v19 候选 40 根和 197,049 条精确路径经静态独审/root 审查，完整源码/SDK 守卫通过；新 owner ACK、Linux 挂载和图尚未发生。

## Boundary

- Boundary: Bionic/Musl 与 Device/Tooling 的进度证据边界。
- Android behavior: AOSP16 R4 原版 APK 需要真实 Activity 冷启动证据。
- OpenHarmony mapping: OH7.0.0.39，App 内单 Bionic，进程外服务可 Musl。
- Fix layer: 本提交仅刷新任务汇总，未修改 adapter。

## Evidence target

- What this proves: 截至核对时点的已接受数量、G274 实际终态、精确 R4 输入准入与 Vivaldi 原包载荷。
- What this does not prove: 整工具完成、安装、冷启动、上屏或设备验收。

## Environment

- Host: 当前 macOS 外环，固定 Linux x86_64 容器进行 G273 宿主构建。
- Device: 本次汇总未访问设备，沿用项目 HOLD 与白名单。
- Tool path: scripts/nanhai_plus_env.py 与候选 executor.py，精确收据见 JSON 索引。
- Artifact path: .nanhai-plus-runtime/bionic-oh7-aosp16/out/bionic-stock-bionic-target-graph-v5/accepted-host/soong_build。
- App: 当前没有 APK 冷启动接受收据。

## Status

- Label: build_pass
- Why: 仅 G262 进程外库及宿主引导产物有局部构建证据；G274 整体图生成失败。

## Observed wall

- Classification: observed
- Fact: G274 实际在 Soong bootstrap blueprint 报出 `kernel-config-soong-rules` 和 `soong-selinux` 两个未定义模块；G273 的 12 种缺项为历史。
- Evidence: G274-REVIEW.json、独立复核 REVIEW.json，SHA 见 TASK-SUMMARY.json。
- First failing command: G274 stock 的 target-graph 子步骤。
- Exit/status: 外层 terminal rc2；目标编译命令 0。

## Hypotheses

- Candidate: G275 需核对这两个定义的精确 R4 来源与 stock 视图；尚无 G275 执行准入。
- Cheapest falsifier: 先核 G275 两个定义的精确 R4 来源与 stock 视图，再经独审、新 ACK 和封包执行。
- Blocking: no

## Proven

- 38/89 历史 Musl 源码接受、77 个原包载荷接受、73 个完整静态清点。

## Not proven

- Bionic 整工具与 APK 冷启动；G274 已运行且图未通过，产品配置成功门也未通过。

## Failed

- G274 图分析 rc2；G273/G272/G271/G270/G269 历史图失败；G268/G267 历史图失败；Firefox 下载 SHA 不符；VLC/Signal/Keychain/Seal/Briar 历史 v2 静态清点失败已由 v3 新证据修复；第 5、12 批整体 rc2。

## Next evidence

- Command: 先核 G275 精确 R4 模块定义与 stock 路径，再经独审、原 owner 新 ACK 与封包运行新候选；G274 不重放。
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
- CI: 执行 JSON/证据索引一致性核对与 git diff --check；未改变 CI。
- Review checklist: 历史 Musl、当前 Bionic、下载、静态清点和设备验收独立计数。
