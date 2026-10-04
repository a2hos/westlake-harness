# EVO-0014: native 后缀与超时分流局部试验

时间：2026-10-04 06:58 UTC。专职 peer 在 120 秒上限内闭合。局部验证改进 1 项，推广 0 项，89 整工具增量 0。没有修改 batch12-v2 冻结包、权威计数、设备或 Herdr。

三组实际输入：G271 terminal rc2，stock Soong 在 5 个 `aidl_interface` 与 1 个 `xsd_config` 类型处停住，目标编译 0；A2 四份原始 APK 仅 raw 接受；batch12-v2 四个静态候选中 2 个完整、Seal rc2、Briar 90 秒超时。这三组结果处于不同证据层级；本试验仅针对第三组的结果分流。

反复成本：扫描器把 `lib/.../*.so` 后缀直接当 ELF 断言。Seal 的 `lib/arm64-v8a/libaria2c.zip.so` 在该断言处失败；冻结收据记录 rc2、未形成 DEX/ELF 完整清点。Briar 被 90 秒 watchdog 杀死，虽然已有 3 个 readelf 返回，但 DEX/ELF 清点未返回。两种失败若只看部分输出，均可能被误读为完整静态扫描。

唯一改进：在扫描结果的只读消费端加入明确分流。仅当冻结 `elf_header` 检查失败、该 APK SHA 与长度仍匹配输入清单、ZIP 成员唯一且实际前四字节不是 ELF magic 时，标记 `SO_SUFFIX_NON_ELF_UNRESOLVED`；这个标记不宣称它是有效 ZIP、不将其计入 ELF，也不使整包扫描通过。仅在收据同时有 `timed_out=true` 与 kill rc=-9 时标记 `TIMEOUT_PARTIAL_ONLY`。完整候选要求 rc0、非超时和完整候选位。其他组合保持 `UNRESOLVED`。这是给后续独立处理提供明确原因的局部观察，未替换扫描器策略。

本地试验：`python3 docs/nanhai-plus/evolution/EVO-0014-native-suffix-timeout/pilot.py` rc0；[TRIAL.json](TRIAL.json) 显示两份完整候选、Seal 的 `504b0304` 成员前缀及 `SO_SUFFIX_NON_ELF_UNRESOLVED`、Briar 的 `TIMEOUT_PARTIAL_ONLY`。四个负例全部保留 `UNRESOLVED`：只有后缀却没有失败断言、成员为 ELF magic、超时标志与 kill rc 不一致、rc0 但缺完整候选位。该试验复用冻结收据和原 APK，只读读取，未重新运行扫描器。

因果预期：后续同类失败可被分配到“后缀与内容不符”的分类调查或“时间预算/复杂度”的扫描调查，同时完整候选仍单独验收。这里没有测得节时，也没有证明 Seal 成员内容、Briar 超时根因或任何 runtime 兼容性。

撤销条件：若独立复核发现成员哈希/输入身份漂移、同一成员重复、ELF magic 检查误判、超时 rc 语义变化，或该分类使任何不完整包进入完整静态计数，立即撤销此消费端分流并回到冻结原始失败收据。后续若改扫描器，须新包、新 ACK、独立审查；本试验不授权重跑。
