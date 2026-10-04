# EVO38 — 200 APK 容量按包身份分层投影

开始 2026-10-04 17:07:21 UTC，结束 17:08:56 UTC，95 秒。依据最近已闭合结果：G311 VyprVPN 黑盒资格 root SHA256 `583a71d47339ddf1ee97c9a5b0b7ac35376ff8693764189e6b7ecf010087e2ee`；G279 four-path 只读 root `9ac26c3804d1d5119601f49baee57878096e49567e86153a8ba952bd32a311c7`；graph 尝试 root `1193163ce45860e208213b4f53cca557422117730533837e259e86d7650721a4` 明确认定仅本地 SSH connect timeout、rc255、无远端 graph 结果；G314 Brave 原包 root `1dac180763a7c0d543676a3b11efcffa855954c23d370e40964ce03c71bfa9f5`；G312 WhatsApp 原包候选及 G313 Telegram HTTP 500。具体包级源文件 SHA 见 `OBSERVATIONS.json`。

假设：200 APK 项目若直接按下载任务、候选文件或 scan 次数投影容量，会把已有包的新版本、无 APK 的请求失败、原包与黑盒资格的同一包重复占位。EVO36 处理消费者字段形状，EVO37 处理稀缺远端传输前审查；本轮只处理包级组合容量。

**唯一改进候选：给 APK 招募批次生成只读“包身份 × 证据层”容量投影。** 以精确包名联接 root raw、root 黑盒资格和已有包记录；每个包在每一层最多增量 1，版本更新单列，HTTP 失败列为无原包。投影不改变正式总账；原包、黑盒资格、冷启动仍由各自 root 收据决定。官网来源仍需逐包精确页面→载荷审查，投影不能替代它。

小范围离线 pilot：`python3 -B docs/nanhai-plus/evolution/EVO-0038-package-capacity-projection/probe.py` rc0。四个近期对象中，VyprVPN 同一包贡献新增 raw 1 与黑盒资格 1；Brave 仅 raw 1；WhatsApp 本次为已有包版本候选，新增 raw 0；Telegram 最终 HTTP 500、无 APK，新增 0。投影为新增 raw 2、黑盒资格 1、冷启动 0。它只复现四个已知个案，未覆盖全量 200 候选，也不证明软件可启动。

推广前须在下一批 ≥20 个候选中与独立 root 总账逐包对账，要求包名冲突/版本更新/缺官网精确对象/缺 APK 全部显式分流且零误增；若出现 split package、同包多发行渠道、证书变更或同名不同产品导致错误合并，停止推广并扩展身份键。G279 graph connect timeout 仅作为执行主线事实记录，不应挤占 APK 容量或被本投影解释为 graph 通过。

未执行网络、SSH、图、设备、容器；未改生产控制、TASK-SUMMARY 或任何既有收据。
