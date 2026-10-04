# G302 Valve 官方原包两枚：raw 候选

- Goal: 为 200 APK 原包池补两枚不同 package 的海外主流黑盒候选，并记录 EVO31 双分支小试的真实起点。
- Original source: [Valve 的 Steam Mobile / Steam Link 下载页](https://store.steampowered.com/mobile) 直接列出 `steam-3.10.9.apk` 与 Steam Link latest APK；保存的两个官方 HTTPS GET 均 HTTP 200，原始响应头和 APK 在项目独立 staging。US-English Google Play 的 [Steam](https://play.google.com/store/apps/details?id=com.valvesoftware.android.steam.community&hl=en_US) 与 [Steam Link](https://play.google.com/store/apps/details?id=com.valvesoftware.steamlink&hl=en_US) 分别为同包名，Valve Corporation，全球 package 下载桶为 100M+ 与 10M+。桶不是这两个 APK 版本的下载量。
- Exact input: `com.valvesoftware.android.steam.community` 3.10.9/code 10470850，131986934 字节，SHA `0c4efad049af622c994a3a7d0e6a0deb291e743cf8dde88bf8cc1669de48020d`；`com.valvesoftware.steamlink` 1.3.32/code 5000315，132207126 字节，SHA `379396e508afd25de7bd3a8bc79ec5da0462e2e9cbf8e47035ce5149b30db459`。
- Host checks: Android SDK 36.0.0 aapt2 与 apksigner 各自 rc0；两包签名证书 SHA 均为 `5dff6b05761447a5bdf919ea88fc6fdf20d301e30b2315415c4d368ec0fbda45`，但没有 Valve 独立发布的指纹证据。ZIP 全量 CRC/唯一成员/manifest 检查通过；Steam Mobile 1816 条、4 DEX、25 ARM64 ELF；Steam Link 134 条、1 DEX、24 ARM64 ELF。全部 ARM64 `.so` 头为 ELF64/AArch64。`CANDIDATE.json` 保留逐包细节与原始流哈希。
- De-dup: APK 内两个精确 package 与彼此不同；在现有 85 raw 的 TASK-SUMMARY 和先前 raw/acceptance 证据中未检出这两个 Valve package。正式 raw 增量仍为 0，需独立复核后由外环接收。
- Timing: 文件 mtime 显示两个下载分别于 2026-10-04 15:34:19.538517Z / 15:34:19.639981Z 完成；候选于 15:35:57.708292Z 生成；`BRANCH-PLAN.json` 于 15:36:19Z 记录。资格和四阶段扫描尚未启动，时间为 null，不能把计划算结果。
- Complete-client blackbox boundary: 本项目输入是 Valve 官网直接下载且未修改的 Android 可执行原包。Valve 的 [Steam Subscriber Agreement](https://store.steampowered.com/subscriber_agreement/) 将 Steam 客户端软件纳入使用许可及知识产权约束；这支持产品层黑盒判断，却不能证明这两个精确版本的完整 Android 客户端源码在任何地方都不存在。公开组件或 SDK 也不能直接当成完整客户端源码。Steam Link 的适用条款范围须在资格审查时单独核验。
- Next: raw 独审/root 准入后，黑盒资格与四阶段静态扫描可基于相同 APK SHA 分支推进；各自独审与 root 准入。签名发布者绑定缺证、完整客户端源码边界待资格复核。原包未修改；无设备、容器、namespace、Bridge 或运行声称。
