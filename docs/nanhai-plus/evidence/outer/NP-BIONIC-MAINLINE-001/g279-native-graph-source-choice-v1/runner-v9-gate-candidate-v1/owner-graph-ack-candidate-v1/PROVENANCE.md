# Graph-only owner ACK 来源门（候选，未派发）

`REQUEST-CANDIDATE.json` 使用新 nonce `4117b3c9f5fcc2eeccdd8c0e7aec071d`、原 `goal_01` / `NP-MUSL16-ART-024` / `oracle-kimi:local:nanhai-plus#inner`、run-id `g279-native-graph-v7-once`、v7 runner SHA/41813 字节与 v9 EVO19 spec 模板 SHA，明确 graph-only 意图以及 target/device/container 禁令。模板的部分远端 size/mode 尚未由新 v7 readback 核实，所以 request 与 spec 均 `dispatchable=false`；consume CLI 返回 rc3，不产生 ACK。若以后补齐 spec，必须重新形成完整请求和新 nonce，并重新独审其 SHA。

真正的原 owner ACK 要经已有 Herdr `nanhai-plus` / `octos-inner` 原会话投递，不能新建 goal/session/agent。外环记录请求精确 SHA、nonce、投递事件；原 owner 在该会话中执行已复审的 consume 命令，原生 JSONL 应出现精确 argv、工具退出码 0、ACK 输出路径和 SHA。独立 peer 在不同写集核对 JSONL 会话/线程连续性、请求/脚本 SHA、nonce、ACK 内容与失败边界，保存 JSONL 片段 SHA 和 REVIEW。queued、prompt-accepted 或仅有 ACK JSON 均不能代表原会话完成。

更严格的执行授权还需独立信任域：当前 v7 graph runner 只验远端同 UID JSON 自洽，可由同写者伪造，原会话 JSONL peer 收据也尚未接入 runner。后续 runner/outer wrapper 必须固定并验证外环与原 owner 不同私钥的签名，或等价的不同权限主体授权通道；无此机制时，即便独立 peer 确认 ACK 来源，`--run` 仍 NO_GO。本候选未联系 Herdr、原 owner、gz02 或设备。
