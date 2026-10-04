# 南海 plus 外环入口

当前目标为 OH7.0.0.39 / android-16.0.0_r4 / ARM64 / App 单 Bionic。进入 App 进程的 OH 客户端依赖按 Bionic 重建；OH 服务可保持进程外 Musl。构建、扫描、测试、桥接与 App 运行均禁止容器及 namespace 隔离，历史容器包不得重放。原 goal、session、claim、累计预算及 200 亿上限保留。活动架构与执行顺序以 [Agent Spec](AGENT-SPEC.md)、[ExecPlan](EXECPLAN.md) 和 [外环 Prompt](OUTER-PROMPT.md) 为准。

项目设备仅限 **5CE24、61AD、5CE12、5CE2D**；安卓 D600 仅作只读对比；其余 D600 禁用，直到用户明示。完整串号与每次命令前的默认拒绝规则见 [DEVICE-ACCESS.md](DEVICE-ACCESS.md) 和 `state/device_access_policy.json`。历史记录不能恢复旧设备权限。

从 [当前卡点和下一步](BLOCKERS-CURRENT.md)、[OUTER-STATE](OUTER-STATE.json)、[原86项进度](A86-REPRODUCTION.md) 读取最新收据和计数；本入口不复制动态计数，避免旧摘要覆盖新状态。最新观察时间随对应收据保存。

[全部工具目录](tool-records/INDEX.md) · [本机看板](http://127.0.0.1:8767/)
