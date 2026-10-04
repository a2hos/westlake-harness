# G279 v2a v3：防后代逃逸的本机配置检查候选

v1/v2 与各自 peer NO_GO 保持原字节。v3 沿用 v2 已通过的源 SHA、root-owned 进程与 Unix 对端 PID/UID、当前叶节点二次回读、严格节点字段树和私有 0700/0600 配置门；只改本机 `mihomo -t` 子进程边界。固定 macOS Seatbelt 策略现在同时包含 `(deny network*)` 和 `(deny process-fork)`。这是原生宿主进程策略，不是容器或 namespace，也不改全局代理或网络配置。

无凭据负例在同一策略中尝试 `fork()` 后 `setsid()`：rc1、EPERM、无 `ESCAPED` 标记；显式 `posix_spawn()` 同样 rc1、EPERM。`runner.py` 在写真实私有配置前再次执行这两项短负例；任何一个失败即停。无凭据 fake-node 用 exact bundled Mihomo 在同策略下 `-t` rc0，且原进程组清理/回读仍保留。fixture 保存两项负例的原始 stdout/stderr 与 SHA，29/29 通过。

该结果支持所测 fork/posix_spawn 路径无法脱离原进程组；不把有限测试表述成所有内核路径的形式证明。真实选中节点的 parser 网络请求尝试仍未知，也未证明真实 `-t` rc0、代理可达或 gz02 已连接。即使将来独立 peer/root 放行 v3，运行范围也只限一次本机私有配置检查；v2b/v2c 仍各自需新门。当前没有 peer GO、root release、START 或 TERMINAL，未使用真实凭据。

超时或失败时先对原进程组 TERM/KILL，再回读非僵尸同组 PID；不确认清空就保留 0600 私有目录并终态 NO_GO，不能重试。强制 SIGKILL/断电的遗留目录仍由 START nonce 指向，需独立人员核进程后精确清理。
