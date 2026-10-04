# EVO36 — 在交接前对齐收据生产者与消费者接口

- 窗口：2026-10-04 16:37:05–16:38:25 UTC，80 秒内闭合。
- 实得结果组：C4 v3 只读预检 rc0（`preflight-TERMINAL.json` SHA256 `9c2c3025d60678d4aa2332eb2b0b69610adbf9806e67a79a5273e8f34fe0fdb2`）及独审；peer 收据 v1→v2；G310 AdGuard exact APK 原包准入和静态准入；原 owner C4 stage-only ACK 签名 provenance。对应独审/准入 SHA 分别为 `635f88f52b1a41c104e6adbdc4bb215f01b57ee5c6c9487e698556e502fc043c`、`f6458306295ce4f393d5fe5fb1dc0aaf45e692d9ae961702443c311a50469376`、`2ce831860037d0dda497561d1fb840b4af2d37c6ae1eda40c89a988477b25ce4`、`a40204019280abb636f44965077530a0eb9ba201dc69acd882b59eac9891edf0`。精确文件及 peer v1/v2 SHA 见 `OBSERVATIONS.json`。
- 先核 EVO35：其字节/授权链探针能阻止伪造执行就绪，解决的是收据真实性；当前 C4 preflight 的实际 v1 peer 通过独审，却与 `freeze_stage_packet` 的顶层字段接口不合，需另发 v2。这不推翻 EVO35，也不把静态或 stage-only ACK 升格成执行授权。

**唯一改进：在生产者收据首次交接前，离线扫描紧邻消费者读取的顶层字段，并对草稿收据做形状探针。** 只报告缺失键，让生产者一次对齐 schema；不进入生产门禁，也不等远端操作。C4 消费者 `freeze_stage_packet` 明确读取 peer 顶层 `decision`、`terminal_sha256`、`stdout_sha256`。v1 把两个 SHA 放在嵌套 `evidence_sha256`，导致顶层缺失；v2 补齐。G310 原包/静态分层准入表明跨阶段复用证据时需要精确对象关联，不能仅凭阶段标签推断接口可接。

小试：`python3 -B docs/nanhai-plus/evolution/EVO-0036-consumer-contract-shape/probe.py` rc0；AST 从真实消费者函数提取字段，v1 检出两个顶层缺口，v2 匹配；root v1/v2 的这三个顶层字段均匹配。首次试跑因探针自身相对路径写错报 FileNotFound，修正定位后通过；这是小试脚本错误，没有触及生产流程。未来可在 receipt 草稿完成时运行一次，输出字段差异并交给原责任人处理；若消费者使用动态字段或 schema 映射，AST 结果须人工复核。

局限：形状匹配不验证值、原始字节、签名、权限、nonce，也不证明 C4 stage/graph 或 APK 启动。未改 `launcher.py`、门禁、控制状态或任何现有收据；未发 SSH、Herdr、设备或容器操作。本轮不阻断 C4 主线。
