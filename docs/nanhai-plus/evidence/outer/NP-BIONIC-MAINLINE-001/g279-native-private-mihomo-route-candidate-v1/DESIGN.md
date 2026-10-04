# G279 私有原生 mihomo 离线候选

本轮结论仅为 `GO_OFFLINE_DESIGN_ONLY`。活动 `verge-mihomo` 进程以当前 `clash-verge.yaml` 运行；该文件 SHA-256 为 `6d11128415287b191dff62c1d28095e01b4d559ef57847c78f188077b9c411a1`。其规则模式中，`GEOIP,CN,DIRECT` 位于倒数第二，末尾为 `MATCH,PROXY`，没有 gz02 `/32`。文件还含 12 条前置规则、健康检查组、DNS 与全局控制 socket，不能原样复制到第二实例。源文件包含节点凭据；本目录不保存、打印或提交它们。

下一轮如获外环单独放行，生成器须先重新核活动进程 `-d/-f` 与源 SHA；在内存中只取一个明确选定且非 `DIRECT` 的完整节点对象。选择的节点可用性目前未知，不能根据组名推断。只将这一个节点和一组 `PROXY` 写入 `.nanhai-plus-runtime/bionic-oh7-aosp16/proxy-pilot-g279/` 的私有配置，目录 mode 0700、文件以 `O_EXCL` mode 0600 创建；该根已由 `.gitignore` 排除。不得复制原文件的前置规则、原 `proxy-groups`、DNS、TUN、控制 socket、secret、profile 缓存或其他 14 个节点。项目证据只记源/生成器哈希、配置安全字段与脱敏结果，不留私有配置字节或节点名。

私有配置固定 `mode: rule`、`allow-lan: false`、`bind-address: 127.0.0.1`、`tun.enable: false`、`dns.enable: false`、`profile.store-selected: false`，只开一个独立的 loopback `mixed-port`；控制端口与 Unix socket 均禁用。规则严格为 `IP-CIDR,1.95.90.207/32,PROXY,no-resolve`，随后 `MATCH,REJECT`。单节点 `PROXY` 组不得包含 `DIRECT`、其他组或健康检查类型。端口在启动前检查占用，绑定失败即终止，不换成全局 7897，也不改变系统代理、全局 Clash 模式或规则。

本轮只用无凭据 `mock.yaml` 做 `mihomo -t -d <隔离目录> -f <mock>`：rc0；离线路由判定确认唯一 IP 走 `PROXY`，相邻与其他 IP 走 `REJECT`。该 mock 的 `PROXY` 成员是 `DIRECT`，**仅用于语法测试**，不代表真实私有配置或代理连通。真实单节点配置仍需另一次 `-t` 校验和源 SHA/权限/无多余规则复核；此轮没有生成或运行它。

下一轮最小可证伪顺序：先校验选定节点、私有配置、独立端口与 `-t`；启动时只记录子进程 PID 并验证监听仅属于该 PID 的 `127.0.0.1:<port>`。先向保留测试 IP 通过本地 SOCKS5 请求，必须被 `MATCH,REJECT` 拒绝；再以 G279 已冻结的 SSH 主机密钥/别名约束，通过 `nc -X 5 -x 127.0.0.1:<port> 1.95.90.207 58222` 做一次有界只读握手。任何规则、端口、节点或 SSH 身份不符均停，未知网络结果不重试。实验结束只终止所记录的私有 PID，确认监听消失，再安全删除该隔离目录中的私有配置；原 Verge 进程和全局配置始终不动。这个顺序目前只是候选，未授权连接 gz02，也未证明代理可达。
