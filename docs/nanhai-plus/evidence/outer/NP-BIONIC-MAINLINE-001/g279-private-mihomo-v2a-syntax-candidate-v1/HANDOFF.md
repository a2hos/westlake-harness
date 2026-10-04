# G279 私有 mihomo v2a：仅本机语法门候选

本候选只允许一次性生成项目私有配置并运行 `verge-mihomo -t`。没有 root release 与独立 peer `GO_V2A_SYNTAX_ONLY` 收据时，`runner.py --execute` 会在 `START.json` 前拒绝。此轮两者均不存在；本轮没有读取真实节点、访问真实控制接口、启动代理或连接 gz02。

v1 的 root-owned socket 阻断不能通过把 `st_uid` 改成任意用户来绕过。v2a 先锁全局配置 SHA、唯一活动进程的 UID/RUID=0、二进制及 `-d/-f` 路径；对 root-owned Unix socket 连接后用 macOS `LOCAL_PEERPID` 和 `LOCAL_PEERCRED` 核对**连接对端**正是该 PID/UID，再核 socket inode 未替换。现有控制接口在没有 Authorization 时也返回 200，Bearer 不能作为安全证明；v2a 不发送 Bearer，安全门建立在内核对端身份及全局配置精确锁上。控制接口只在内存中返回当前 `PROXY` 链的叶节点名，不写入收据。

程序只从源配置取这一条叶节点对象，在被 Git 忽略的项目 runtime 中以 0700 目录、O_EXCL 0600 文件生成最小 YAML；规则固定为 `IP-CIDR,1.95.90.207/32,PROXY,no-resolve` 和 `MATCH,REJECT`。不复制其他节点、前置规则、健康检查组、DNS、TUN、控制接口、secret 或系统代理设置。`mihomo -t` 的 stdout/stderr 只在内存中摘要；公开终态记录阶段、rc、字节数、SHA 和有限类别，不输出凭据或节点名。正常结束或失败立即移除私有 run 目录。若进程遭强制 SIGKILL/主机掉电，`START.json` 的新 nonce 对应 `once-<nonce>` 私有目录，须在确认没有相关进程后由独立人员做精确目录清理；不可重放本次 START。

无凭据 fixture 使用 fake socks5 节点、本机 `socketpair()` 内核 peer PID/UID 与 `mihomo -t`。它证明代码分支、macOS peer API 和无凭据语法形状，不证明真实叶节点、真实配置的 `-t` 成功或任何代理/SSH 可达。v2b 监听和路由、v2c gz02 SSH 均不在该 runner 的执行路径中。
