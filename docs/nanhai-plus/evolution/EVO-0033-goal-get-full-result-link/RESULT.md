# EVO33 — Goal_get 完整结果留存与原事件联结（隔离小试）

- 触发：G302 raw、G303 黑盒资格、G304 四阶段静态各有实际 root 接受；A3.0 连续性在一次原会话 `goal_get` 成功后仍为 `NO_GO_A3_0_FULL_CONTINUITY`。四组精确收据 SHA 见 `OBSERVATIONS.json`。本次方向与 EVO31 黑盒分支、EVO32 S1 typed receipt join 不同。
- Problem: 原生 ledger 的 `tool_completed` 仅留 203 字节截断 `output_preview`，无法把预算、累计用量、创建身份的完整结果与 `tool_call_id` 交给独立审查。
- Repeated cost: A3.0 v1/v2 两次 NO_GO；后者找到 17 小时前 supervisor 快照，却仍不能把历史用量当当前结果。若继续用 owner 叙述或旧快照补全，会重复审查且无法释放 A3。
- Decision to improve: 对**未来一次经单独授权的原会话 Goal_get**，原生工具层保留完整结果原字节为独立只读 blob，记录 blob SHA、字节数、原 session/turn/tool_call_id 与完成事件 seq；peer 对同一事件联结后再解析字段。不要由人工叙述或截断 preview 代替原字节。
- Constraints: 不改现有 A3/graph、设备、容器或 Bridge；本目录不调用 Herdr、不投递 owner、不制造实际 Goal_get 结果。仍需独立 claim/coordinator/live goals-sessions 证据，完整 Goal_get 自身不能证明全部 18 字段。
- Completion evidence: `probe.py` 本机 rc0；现有真实 preview 被拒，合成完整 JSON 联结通过，错 digest、tool ID、session 均被拒。见 `PILOT.json`；正例只证明校验机制，**不证明 live goal**。

观察：G302、G303、G304 的逐阶段原字节和哈希让并行结果可各自审查；A3.0 的信息缺口则位于原生工具输出持久化。推断：若下次原生 Goal_get 成功时完整字节与完成事件一并保存，可消除以旧 supervisor 事件反复补字段的工作。未知：Herdr/Otty 当前是否提供可无损截获完整 tool response 的接口；若没有，须在原生工具结果写入路径做最小改动并另行审查。

丢弃的旧动作：把 `OUTER-STATE` 的 255,945,577 历史用量或 owner 叙述当作 2026-10-04 当前 Goal_get 证明。A3.0 v2 审查 `5a380503...` 已核其 supervisor 时间比目标读取早约 17 小时；该替代动作不能闭合当前性。替代动作是同一 tool-call 的完整结果 blob 与 digest 联结。

因果链：截断 preview 与旧快照反复补证 → 缺少完整结果字节及事件绑定 → 内容寻址 blob＋session/turn/call/seq 联结 → 避免再次扫描旧快照和重写 owner 叙述 → 以真实新读取中完整字段、SHA、审查结果及节省的重复轮次验证。

小试结论：**候选保留，未推广**。只建议下一轮在原生工具结果持久化的单一 Goal_get 事件上试用；若完整原字节不能与原 `tool_call_id` 稳定绑定，或比对后字段仍缺失，立即停止推广并保持 A3 NO_GO。不得把合成正例计作 A3 连续性通过。

适用：Nanhai-plus 原 goal_01 / 原 `oracle-kimi:local:nanhai-plus#inner` 的未来只读元数据工具结果，亦可供其他有截断 preview 的工具评估。反例：若权威当前状态存储已经原子保留完整结果且可证明 session/turn/call，则额外 blob 可能冗余；先比较现有接口。风险：blob 可能含敏感字段，应沿既有证据目录权限和保留策略处理，并只记录必要字段，不向看板暴露原文。

方法/过程数据：`OBSERVATIONS.json` 锁四组输入收据；`probe.py` 与 `PILOT.json` 锁离线命令、rc、SHA、正反例。反思启动时刻未单独打点，故不声称精确耗时或已满足 120 秒上限；本次只有一个技术改进和一个隔离小试，主线未被阻塞。无 memory/skill/CI/canonical 更新。
