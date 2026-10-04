# G279 原 owner graph ACK：独立会话来源接入方案（未执行）

现有 `owner-sync-v1/ACK-REVIEW.json` 只证明原 `oracle-kimi:local:nanhai-plus#inner` 会话消费了源码和环境元数据。它明确不授权 graph。v7 runner peer 已证明，同一 gz02 UID 可自写三份相互一致的 JSON；文件 mode 0444 和互引 SHA 不能证明来源。

下一次应先冻结外环请求，包含新的不可复用 nonce、`goal_01`、`NP-MUSL16-ART-024`、v7 runner 精确 SHA/大小、graph-only argv、新 v7 EVO19 gate/spec/probe SHA、目标编译与设备禁止位，以及外环请求 SHA。仅向**原** Herdr `nanhai-plus` / `octos-inner` 会话投递；原 owner 在其独立证据目录消费请求并生成 graph-only ACK，回写同一 nonce、请求 SHA、runner SHA、会话标识和 `graph_executed=false`。本方案没有投递请求。

独立 peer 必须读取原会话的原生 JSONL 片段与监控事件，核对精确工具命令、退出码 0、ACK 文件 SHA、会话/线程连续性、nonce 与请求 SHA；参照此前 `owner-sync-v1/ACK-REVIEW.json` 的 line-slice SHA 方法，但不得沿用旧 metadata ACK 充当 graph ACK。peer 将核验收据保存在外环独立证据目录，外环 release 引用该收据 SHA。queued 或 prompt-accepted 仍只是交付状态。

这只建立**审计来源**。当前 v7 runner 仍只读取同 UID 的远端 JSON，不能自行验证外环 peer 的真实来源。真正解除该伪造风险需要下一版执行门：由外环与原 owner 分别持有远端同 UID 无法读取的签名私钥，runner 固定并核验两枚公钥、nonce、runner/SPEC/ACK SHA 和一次性 release；或者采用等价的不同权限主体、可独立验证的授权通道。若没有独立密钥或权限边界，保持 `--run` NO_GO，不以自签 JSON 放行。

最便宜的下一证据是先静态审查请求/ACK/peer 验证脚本与签名或权限边界，再做一次不执行 graph 的原会话 metadata 挑战演练；演练通过也仅证明授权链，真实 seccomp/后代清理和 EVO20 子 Ninja 闭合仍单列。不得因为本 staging 候选或原 metadata ACK 而触发 graph。
