# G252 历史阻塞快照（非当前执行入口）

当前目标为 App 单 Bionic、全流程无容器，历史 Musl 与容器结果单列。下表是 G252 时点的历史快照，不能用作当前执行入口或进度；当前事实以 [RESUME.md](RESUME.md)、OUTER-STATE 和最新检查点为准。原 goal/session/claim/累计预算保持。

| 范围 | G252 时点事实 | 当时下一证据／当前约束 |
|---|---|---|
| Bionic 源码 | 完整 R4 3359 个源码对象已准入为保留大小写的归档；官方树根一致，仅排除 8 个精确 Mac 元数据 | 项目独立大小写敏感展开并绑定真实 ARM64 CRT/libc/linker、工具链及 stock 配置 |
| 宿主构建 | G252 曾在容器中完成 stock soong_ui 宿主 bootstrap；该结果只作历史证据，不计原生构建通过 | 使用经版本核验的普通原生 Linux 宿主进程、只读 R4 源码和本项目独立 OUT/TMP/staging；禁止 Docker/Podman/OCI 及 nsjail/unshare/chroot 等替代隔离 |
| 安装服务 | GZ02 真实 ARM64 crypto/zlib 存在，48 个头文件一致；推导的 producer 源目录已不存在，构建时源码 pin 未闭合 | 保留现有产物来源缺口；取得生产收据或按已核 OH39 源独立重建所需提供方，不依赖未知来源库 |
| 图形/Input | surface/native-window 是完整多 TU 生产模块；存在 mapper/VDI/GPU 和 libframe_ui_intf.so 动态加载边界 | Bionic C++/CRT、产品 GN/HDI 生成输入和全进程内依赖闭包；真实 WMS/RS、FD/buffer 所有权及 R4 consumer |
| HelloWorld | 新 Bionic 代安装、冷启动、上屏、输入和正常退出均未验 | 基座就绪后沿最早实际失败边界执行；不等待其他项目整体上屏 |
| 89 项 | 88 项归属计划已复核，1 项 ART abort bridge 待定；32 重建、51 替代计划、5 条件保留；Bionic 工具验证 0 | 逐项真实消费者验证；ART abort caller/日志出口身份；历史 Musl 38/89 不迁移 |
| 控制链 | G252 时原内环曾因 Docker context 不可见而委派宿主执行；该委派和旧包均不恢复容器授权 | 沿原唯一 claim 封包和反馈，旧容器包拒绝执行；原生主机包须有新的 owner ACK、独审和外环放行 |

本历史快照来源为当时 OUTER-STATE、G252-ACCEPTANCE 和相关证据包。后续进展及反思节奏以最新控制记录为准。
