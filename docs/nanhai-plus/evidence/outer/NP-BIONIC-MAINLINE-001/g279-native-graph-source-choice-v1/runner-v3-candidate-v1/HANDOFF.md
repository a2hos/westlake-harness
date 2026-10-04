# G279 原生构图 runner v3 静态候选

`scripts/nanhai_plus_native_graph_v3.py` 只允许本机 `--static-check`。`--run` 固定返回 3 并写明 `NO_GO_GRAPH_RUN_REQUIRES_NEW_REVIEWED_RUNNER`；目前没有构图派发权限。保留 v1/v2 原样，未访问 gz02、容器或设备。

静态检查命令：`python3 -B scripts/nanhai_plus_native_graph_v3.py --static-check`。实际 rc0；`--run` 拒跑测试 rc3，AST 解析 rc0，命令与输出哈希见 `STATIC-CANDIDATE.json`。

代码候选从冻结的 `g279-native-graph-env.json` 构造所有路径，并核三份已投递只读输入。源守卫扩到 manifest 全十条根链接、根拓扑、旧 out/.repo.failed 排除、权限、1011 仓无 untracked 和前后 ledger。未启用的执行路径加入 Linux subreaper 与 `/proc` 后代清理、no-namespace guard 前置、exec/namespace 系统调用 trace、精确 `build.aosp_arm64.ninja` 和完整 tracked `Android.bp` 覆盖检查。生成 Ninja 动作安全与目标编译分别判定，不能从构图成功继承。

独立 peer 需检验根拓扑推导、远端文件身份、异常后的进程树清理、seccomp 继承与 trace 完整性、BP 覆盖算法；这些检查尚未在真实构图中运行。即使静态审查通过，也需另一个明确的 graph-release 包和原 owner ACK。当前 Soong 图、ARM64 Bionic 编译、HelloWorld 冷启动与设备结果均为零。
