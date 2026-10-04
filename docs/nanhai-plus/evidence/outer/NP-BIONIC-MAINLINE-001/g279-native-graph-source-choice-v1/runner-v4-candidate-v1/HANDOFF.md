# G279 runner v4 静态候选

`scripts/nanhai_plus_native_graph_v4.py` 的 `--run` 仍硬拒绝，返回码 3。可达的 `--static-check` 只读取本地既有收据；没有 SSH、构图、容器或设备调用。

本轮集中修 B4/B6 的可测试边界。未启用的执行路径接管 SIGTERM/SIGINT，在 `finally` 中尝试清理并确认后代为空，再恢复原信号处理；一旦无法证明后代已清空，跳过源后检并保持失败。预检失败可写入固定项目控制目录的一次性 `RESULT.json`，写入使用 `O_EXCL`、`O_NOFOLLOW` 和 fsync。精确构图产物只接受 `soong/build.aosp_arm64.ninja` 与非空 `.module_paths/Android.bp.list`，另核跟踪的 `Android.bp` 覆盖。

本地夹具对 SIGTERM、SIGINT、收据不可覆盖、精确产物正负例和目标动作不授权共七项返回 rc0；它们使用 mock，不证明真实 Linux 脱离后代清理、seccomp 继承或远端产物。生成 Ninja 的词法扫描仅标 `LEXICAL_SCREEN_ONLY_NO_TARGET_AUTHORIZATION`；目标编译始终未授权。EVO19 所需 runner/wrapper/远端身份/argv/interpreter/SSH 双返回码同收据门尚未实现。独审须基于本版精确 SHA；审查通过也不自动解除 `--run`。
