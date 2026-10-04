# 南海 plus Agent Spec — Bionic 主线

当前用户架构决定取代历史“先 Musl 再 Bionic”。约束正文为 [GOAL](GOAL.md) 与 [外环 Prompt](OUTER-PROMPT.md)，执行层读 [内环 Prompt](NANHAI-PLUS-PROMPT.md)。历史全文和 SHA 保存在 [切换前快照](evidence/outer/NP-BIONIC-MAINLINE-001/root-transition-v1/BEFORE.json)。

## 固定边界

- OH7.0.0.39 / android-16.0.0_r4 / ARM64；App 进程统一 Bionic，进程内 OH client 按 Bionic 重建；OH 服务可在进程外使用 Musl。
- 构建、扫描、测试、桥接和 App 运行全过程禁止 Docker/Podman/OCI 容器及容器镜像，也不以 nsjail、unshare、chroot 或同类 namespace 隔离替代。历史 G252–G276 容器收据仅作历史事实，不是当前架构或可重放执行包；G277/v21 容器候选撤销。宿主构建只能在经版本和工具链核验的普通原生主机进程中，用本项目独立 OUT/TMP/staging 与只读源码输入执行。
- 保留 AOSP Framework/ART/BCP 语义；适配 OS、IPC、JNI、服务和图形输入边界；不新增整套 Android system_server，不以 stub、双 libc、语义补丁或安全降级凑通过。
- Bio3 设计经验需核 AOSP14、ARM32、OH7.0.0.18 差异；BridgeAOSPV16 仅只读并行参考，不等待其整体上屏；本项目独立构建和验证。
- HelloWorld 当前最早未通过环节是关键路径，独立工具与 client 工作同时释放。诊断 APK 与未修改基准 APK 分列。
- 全部原 89 ID 保留，新目标逐项保留、重建、原生替代或退休；退休不能记 PASS，未知适用性不删除分母。历史 Musl 源码接受 38/89 单独保留，不迁入 Bionic 通过数。

## 控制和资源

外环对 goal 完成负责，统一指挥、调度、管理、定时驱动、反馈独审和集成。沿原 Herdr `nanhai-plus/octos-inner`、`goal_01`、native session、claim 和 200 亿预算继续，累计用量不重置。原 claim 名字中的 Musl 仅为历史身份，实际包须显式 target/revision。

基座与依赖、安装与服务、图形与输入为三条并行角色，工具任务按依赖分配；当前最多 4 个活跃 agent 含外环、6 个主机构建子作业、2 个设备槽。专职反思 peer 使用完成/空闲槽，每 3–4 组复核后的实际结果触发一次，最长 120 秒、最多一个可验证改进，方向随证据调整。

路径仅由根 local_env.md 定义，经 env wrapper 注入 NANHAI_*。共享源码只读，源码修改用版本所属独立工作树；产物、临时目录、staging 和运行代属于本项目。每次设备命令重读 policy，完整串号白名单外拒绝。当前设备授权见 [DEVICE-ACCESS](DEVICE-ACCESS.md)，不继承历史设备许可。

## 验收口径

每项结果分别记录 build_pass、stub、real_impl、device_verified 与未证明范围。原始命令、rc、时间、输入/产物 SHA、实际消费者和独立复核不可缺少；设备收据另绑串号、镜像、boot、进程和部署回读。参考、准备、编译和静态闭包不等于上屏。

近期完成条件：HelloWorld 安装、冷启动、真实内容上屏、输入状态变化、生命周期、正常退出和恢复；全部 89 项处置及适用项真实消费者验证。

核心版：未修改 10 APK 闭环，AMS/PMS/WMS 正向、权限负例、生命周期和恢复契约。最终版：原 30 APK、AOSP16 AIDL 全量 interface.method+signature 清单和逐项状态、原 5000+ 系统 API 范围账。Musl 对照仅在有适用证据对时做，不是 Bionic 运行或发布的硬前置；纯 Android 对照仍按原范围推进。性能先测量再按已确认阈值验收；核心和最终发布保留原人工门。


## 当前活动范围扩展：登记全集与 200 APK 启动

用户当前活动目标为：学习 westlake-harness 方法，使用本机 OH7/AOSP16/ARM64 与 App 单 Bionic 架构，真实启动至少 200 个不同原包应用，其中至少 100 个经核验的海外主流黑盒应用。上游登记全集保留并逐项复现；超过 200 个仍继续全集处置，原 HelloWorld、89 项适用工具、10/30 APK 与 API/AIDL 契约目标保留。完整执行规则见 [PORTFOLIO-GOAL](PORTFOLIO-GOAL.md)。

登记、获取、扫描、尝试与成功分列。启动数只计本代原包真正冷启动进入其真实 Activity 生命周期、具有 APK/runtime 哈希、进程身份和运行日志的独审结果；安装、PID、宿主构建与历史通过不计入。上屏、输入与恢复分别验收。200 次尝试不能替代 200 个启动成功。

原 goal/session/claim、累计预算、设备权限和唯一调度器保持。当前执行包继续按冻结契约执行；范围扩展须通过原 owner 的有界元数据回读同步，未取得该收据前不能宣称原生 goal 已同步。
