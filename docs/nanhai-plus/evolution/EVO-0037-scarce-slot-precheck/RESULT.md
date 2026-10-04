# EVO37 — 稀缺远端步骤前的本地失败用例

开始 2026-10-04 16:52:52 UTC，结束 16:53:52 UTC，60 秒；本轮只做一次短反思。输入是四组近期实得结果：C4 stage/readback 根接受（SHA256 `ff1aa9b0d326bd8eefabfb67afa8c2670a72d0d98476448bb2d65cdd1ab72859`）及 readback peer（`c116b10f4f9c6f6940ee4429469858966a5c32f679681d6f0bdfdd90d442750f`）；G311 VyprVPN 精确原包准入（`c6e8e66616c5455ac63d96b56664f64d6f7074303a42eb0bcd22dd89149b78a3`）与四阶段 host static 准入（`36348b4add7e8baa78f56b6a59c6281f2b138e981e3bb4dd91c6c92d3d1c3682`）；L5 一次只读 SSH terminal rc0；以及先前 transport v1 独审 NO_GO。路径、SHA 与试水输出见 `OBSERVATIONS.json`。

EVO36 的 consumer 字段形状预探针已能在 C4 peer v1→v2 交接前指出缺失键。本轮方向不同：减少远端关键路径上的无效尝试。假设是：对新 transport 首次占用远端槽位前，以本地负例检查“实际 stdin 程序 SHA 绑定、固定唯一收据目录、防跨目录重放、release 绑定完整路由和 scope”，可把 v1 一类问题留在本地修复。它不能替代 root release。

**唯一改进候选：把上述四个负例作为新 transport 的本地预审小包，完成后才申请稀缺远端槽位。** 不给每个 APK 重跑这套 transport 检查；同一 transport 版本复用一份已签收证明。G311 的 raw/static 两级结果仍仅为主机证据，不能因此推断 L5 或 APK 启动已通过。

最小 pilot：`python3 -B docs/nanhai-plus/evolution/EVO-0037-scarce-slot-precheck/probe.py` rc0。它只读真实 v1/v3 peer 和 v3 L5 terminal：v1 本地路由=false，v3=true，随后已存在的 L5 terminal 为 ssh_rc0。这个回放说明判别规则与历史结果一致，**不证明节省了多少时间或必然避免失败**；脚本读取 reviewer 声明而非重新执行控制器负例。若推广，先在下一种新 transport 上以真正的合成 stdin 篡改/目录重放用例测能否在 SSH 前失败，并量出增加的本地耗时；超过远端失败成本或误挡正常 release 就撤销。

未改生产门禁、控制文档或既有收据；未执行 SSH、图、设备、容器，也未碰 Bridge。C4/L5/APP 当前权限仍各由原独立根收据决定。
