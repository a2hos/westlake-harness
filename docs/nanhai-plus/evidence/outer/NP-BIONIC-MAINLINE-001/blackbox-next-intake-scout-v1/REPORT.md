# 下一批商业黑盒原包来源侦察（只读）

2026-10-04 UTC。只查现有接受收据、冻结登记和发布者页面；未下载 APK、未访问设备、未改计数或原控制面。当前外环账本为 75 个原始载荷，合格海外主流黑盒启动仍为 0/100。这里的“官方可取”仅指发布者提供分发入口；除了下述固定 Vivaldi URL，页面通常不锁定版本、字节或 SHA，均不能直接进入原包接受集。候选新版本与上游登记历史版本分列，不替换历史 SHA。

| 优先级 | 应用 | 官方入口与已见交付方式 | 黑盒 100 资格前景 | 下一最小证据 |
|---|---|---|---|---|
| 1 | Vivaldi Browser | [官方 Android 页](https://vivaldi.com/android/) 给 ARM64 APK；[官方历史档](https://vivaldi.com/download/archive/?platform=android) 给固定 `Vivaldi.8.2.4147.130_arm64-v8a.apk`，URL `https://downloads.vivaldi.com/stable/Vivaldi.8.2.4147.130_arm64-v8a.apk`，页面约 336.54 MB | 待证，浏览器含专有部分，需完整源码可用性与海外市场证据 | 固定档案页/校验和、HTTPS 与 Content-Length、下载后 SHA/ZIP/签名/package；大包单独预算 |
| 2 | Zoom Workplace | [Zoom 官方 Android 下载页](https://zoom.us/download?os=android) 明示 “Download from Zoom”；其[官方管理文档](https://explore.zoom.us/media/zoom-video-communications-guidance-document-2021-12-06.pdf)确认直接签名 APK | 待证；上游登记 `7.1.8.42948` 不等于当前下载 | 从页面解析发布者目标 URL/版本，冻结后再取件；可能需要账号/服务 |
| 3 | LINE | [LINE 官方主页](https://www.line.me/en/) 展示 APK 选项；[LINE 帮助中心](https://help.line.me/line?contentId=20020931&lang=th)建议从官方站取最新 APK | 待证 | 解析实际官方 APK URL 与版本、发行方签名；本轮未得到固定文件 URL |
| 4 | TikTok | [TikTok 官方帮助](https://support.tiktok.com/en/getting-started/creating-an-account/download-tiktok)说明官网 `tiktok.com/download` 提供 APK | 待证；上游 `47.1.4` 不能用页面“最新”替代 | 用可访问地区/页面记录精确 APK URL 与变体；查 base/split/ABI |
| 5 | TikTok Lite | 同一 [TikTok 官方帮助](https://support.tiktok.com/en/getting-started/creating-an-account/download-tiktok)单列 Lite APK | 待证；须确认不同 package，不能当 TikTok 另一版本重复计数 | 单独冻结 package、版本、URL、签名及海外分发范围 |
| 6 | Epic Games Store | [Epic 官方安装说明](https://www.epicgames.com/help/en-US/c-Category_FallGuys/c-Trending_0/a000090668?lang=en-US)要求点击其站点 “Download on Android” | 待证；新补充样本 | 解析发布者 APK 目标/实际 package/版本，避免把商城内游戏下载算作同一包 |
| 7 | Proton Meet | [Proton 官方下载页](https://proton.me/meet/download)给 APK 链接 `https://proton.me/download/MeetAndroid/ProtonMeet-Android.apk` 与签名证书 SHA-256 `DCC9439EC1A6C6A8D0203F3423EE42BCC8B970628E53CB73A0393F398DD5B853` | 黑盒资格未定；产品较新，主流门槛尤其待证 | 先冻结实际版本与源代码可用性，再取件；证书 SHA 不是 APK SHA |
| 8 | Spotify | [官方 Play 条目](https://play.google.com/store/apps/details?id=com.spotify.music) | 待证；上游 `9.1.86.2432` 只有历史标签 | 经已授权 Play 交付取得完整 base/config/feature split 集及签名；公开条目不是 APK URL |
| 9 | Discord | [官方 Play 条目](https://play.google.com/store/apps/details?id=com.discord) | 待证；上游 `346.13 - Stable` 只有历史标签 | 同上；完整 split 集逐件锁 |
| 10 | Reddit | [官方 Play 条目](https://play.google.com/store/apps/details?id=com.reddit.frontpage) | 待证；上游 `2026.39.0` 只有历史标签 | 同上；完整 split 集逐件锁 |
| 11 | Telegram（200 包控制） | [官方 Android 页](https://telegram.org/android) 的按钮指向 `https://telegram.org/dl/android/apk`，会转临时 CDN URL | **不计黑盒 100**：官方公开客户端源码与可验证构建 | 版本/SHA/签名完整核验后可作不同渠道原包控制；不得替换历史 2-split XAPK |
| 12 | Firefox（200 包控制） | [Mozilla 官方档案](https://archive.mozilla.org/pub/fenix/releases/)可选择精确版本/ARM64 APK | **不计黑盒 100**：源码公开 | 先审当前已存官方变体与历史 SHA 差异；避免重复 GET 或错误继承历史身份 |

这 12 个条目中，7 个有发布者直接 APK 入口，3 个只能从官方 Play 完整交付；2 个开放源码控制用来推进 200 包扫描，不充当 100 黑盒。仅 Vivaldi 在本轮观察到固定版本与直接文件 URL；Zoom 官方论坛另有旧 `5.12.8.9880` 固定 URL，但不属于当前登记版本，未纳入本批。Proton Meet 和 Telegram 的稳定入口会交付滚动版本，不能在下载前虚构 payload SHA/size。此前 WhatsApp 官方新版原包已接受，不再列为新取件。

建议第一批只做 **Vivaldi、Zoom、LINE、TikTok、Epic、Proton Meet 的元数据锁定**，每个页面记录 UTC、最终域名、TLS、HTTP、版本标记、实际文件 URL、Content-Length、内容类型、跳转链与渠道条款；HTTP 页面或商店列表不得伪装成 APK。只有同一渠道/同一版本锁完整，且预估单包/总量预算通过后，另行冻结一次性 GET。下载按每包独立结果保存 HTTPS/最终 URL、实际 bytes/SHA、ZIP CRC/唯一 Manifest、aapt package/version/ABI、apksigner 全方案与签名证书、split 闭合和无修改链；失败/超时/版本不符只保留失败，不换镜像或自动追 latest。全部仍须另核官方海外市场与可用完整客户端源码属性，真机启动单独验收。

现有 [32 商业线索缺口](../mainstream-blackbox-input-readiness-v1/HANDOFF.md)与[官方入口侦察](../mainstream-blackbox-official-intake-scout-v1/CANDIDATES.json)是此计划的来源基线。这里没有实际 HTTP 载荷探测、下载或资格通过，75 原包与 0/100 不变。
