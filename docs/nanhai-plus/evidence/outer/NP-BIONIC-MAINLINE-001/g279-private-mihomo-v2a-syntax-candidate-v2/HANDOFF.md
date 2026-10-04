# G279 v2a v2：本机配置检查候选（未执行真实配置）

v1 候选与 peer NO_GO 原件保持不变。v2 只在独立 peer GO 和固定位置 root release 同时存在时才可产生 `START.json`；本轮两者都不存在。没有读取真实叶节点、写入真实凭据配置或运行真实 `mihomo -t`，也没有启动代理实例、SSH/gz02、设备或容器动作。

修正三处阻断。首先，对当前叶节点完成第一次读取后，在**写私有配置紧前**重新读取全局配置并核 SHA、唯一 root-owned 进程的 PID/参数、root-owned socket inode；再次通过 macOS `LOCAL_PEERPID`/`LOCAL_PEERCRED` 查询当前选择，叶节点变化立即停止。控制接口当前无 Authorization 也返回 200，因此身份依据连接对端的内核 PID/UID，而不是 Bearer。其次，所选节点仅允许当前四类协议的明确字段树；嵌套 `ws-opts`、`reality-opts`、`alpn` 有严格结构与类型，外部文件/证书、额外依赖键和文件 URI 一律拒绝。再次，真实 `-t` 候选命令固定用本机 `/usr/bin/sandbox-exec` 的 `(deny network*)` Seatbelt 策略，不使用容器或 namespace；无凭据 fixture 证实本机及子进程的 loopback TCP 被 EPERM 拒绝，同策略下 exact mihomo binary 的 fake-node `-t` rc0。

这**不证明** exact binary 在真实节点上不会尝试网络。官方同版本源码研究指出解析阶段某些配置可触发 geodata/provider 下载，而打包二进制的源码构建关系未证。v2a 只能称为“本机配置检查；真实选中节点的网络请求尝试未知”。策略旨在限制成功 egress，实际真实凭据路径仍待独立 peer/root 审查。不能将 mock rc0 当成真实节点语法成功，更不能算代理/GZ02 可达。

`-t` 在独立进程组内执行。超时或正常退出都对同组进程做 TERM/KILL 与数字 PID/PGID 回读；确认清空才删除 O_EXCL 0600 私有配置和私有原始日志。若后代存活或身份无法确认，终态为 `NO_GO_DESCENDANTS_UNPROVEN_PRIVATE_RETAINED`，私有目录保留供独立人员依据 START nonce 和进程审计后处理，不能自动重试。终态仅记阶段、rc、输出 SHA/字节数和有限错误类别，不写节点名、凭据或配置全文。强制 SIGKILL/断电仍可能留下 0600 私有目录，必须人工精确清理。
