# G279 v6 EVO19 静态候选（审阅 v2）

审阅入口为 `scripts/nanhai_plus_native_graph_v6.py`、`scripts/nanhai_plus_native_graph_v6_gate.py` 和本目录 `STATIC-CANDIDATE.json`。v1 草稿尚未独审即补充了收据路径绑定与 SSH 外层失败用例；本版收据单列其替代关系，不能引用草稿 SHA 放行。

门候选以现场 `local_env.md` 计算权威摘要，并在远端对 runner、解释器和九项控制输入逐一用 `O_NOFOLLOW` 回读 SHA、大小、权限模式。审定 release spec 还须锁定本地 wrapper 身份、意图远端 argv；单份原子 `EVO19-GATE.json` 同时保存期望与实测身份，以及 SSH 外层和远端返回码。任何身份或返回码漂移先记录失败，不执行图。可审计失败包括环境、收据路径、远端字节、SSH 和重复收据。

九项本地注入夹具返回 rc0，未发 SSH。runner `--run` 与门的 `--preflight`／`--execute` 仍固定 rc3；因此本候选不具备图执行权。原 owner ACK、实际远端回读、Linux 后代清理、seccomp 继承和完整图证据均待后续单独验收。EVO20 的 subninja 动作扫描不在本轮范围，生成动作和目标 Ninja 继续 NO_GO。
