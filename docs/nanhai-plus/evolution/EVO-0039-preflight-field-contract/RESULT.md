# EVO39 — 封包字段契约的离线预检

本轮在四组实际结果后闭合：G315 Brave 嵌入 DEX 漏清点与补充、G279 代理 v1 四路径超范围读取被独审拒绝、代理 v2 获得 root release 后本地 `KeyError` 且 SSH 前终止、G316 CapCut `arm64` 路径内 ARM32 ELF 导致 v1 严格检查 rc1。输入收据及 SHA 见 `OBSERVATIONS.json`。方向为执行封包的字段契约，区别于 EVO38 的 APK 容量投影。

唯一改进候选：在 root release 前用只读 AST 检查器对照 controller `preflight()` 中的字面量 `candidate['字段']` / `release['字段']` 与 JSON 顶层键。字段不齐时停在本地候选阶段，不消耗一次性 release。这是字段形状检查，不代替全流程正例预检、来源哈希、独审或 root 放行。

小范围离线试水：`python3 -B docs/nanhai-plus/evolution/EVO-0039-preflight-field-contract/probe.py` rc0。它在已失败 v2 中准确指出 `candidate` 缺少 `timeout_root_acceptance_sha256`（实际误写 `graph_timeout_root_acceptance_sha256`），而 v2 release 键无缺项；在未发布 release 的 v3 候选中指出 candidate 键无缺项，并明确 release 尚不存在。输出与输入 SHA 在 `OBSERVATIONS.json`；检查器本身为 `probe.py`。

这个单点检查覆盖字面量顶层键；不能证明值正确、动态字段访问安全、远端 SSH 可达或构图成功。推广条件：在下一个封包先与独立正例本地 `preflight()` 结果对照，要求字段缺失零漏报；动态键或多层结构出现时先扩展检查器，不能把本试验直接当生产门禁。未改生产控制、计数或既有收据，未 SSH、设备、容器。
