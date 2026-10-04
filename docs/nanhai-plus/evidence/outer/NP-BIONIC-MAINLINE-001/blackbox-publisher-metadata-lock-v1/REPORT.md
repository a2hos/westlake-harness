# 发布者 APK 元数据锁定：Zoom / LINE / Epic（只读）

核查时间见 `RESULT.json`（2026-10-04 UTC）。实际只对发布者网页作 GET，对 Zoom 历史 APK 作 HEAD；没有读取 APK 内容、下载、计数、设备操作或黑盒资格判断。HTTP 状态、跳转、Content-Type、Content-Length 和页面 SHA 在 `RESULT.json`。

| 产品 | 可锁定结果 | 未锁字段/原因 | 下一来源 |
|---|---|---|---|
| Zoom Workplace | **仅历史版本 5.12.8.9880**：Zoom 员工在[官方论坛](https://devforum.zoom.us/t/host-link-not-starting-meeting/81008)给出 `https://zoom.us/client/5.12.8.9880/zoom.apk`；2026-10-04 HEAD 实得 302 到 `https://cdn.zoom.us/prod/5.12.8.9880/zoom.apk`，最终 200，`application/vnd.android.package-archive`，声明长度 **253224483** 字节；两个域均属 Zoom。它不等于上游登记 7.1.8.42948，也不是当前版本。 | 当前[官方 Android 下载页](https://zoom.us/download?os=android)实测 200 HTML，页面正文无 `apk` 字符串；当前 APK URL、版本、长度未锁。历史版本仅 URL 路径与 HEAD 声明，尚无文件 SHA/签名/Manifest。 | 在发布者站点的移动浏览器/官方下载按钮解析当前直链；或单独选择此官方历史版作 200 包候选，之后才预算受控 GET 和签名核验。 |
| LINE | [官方主页](https://www.line.me/en/)实测 200 HTML；[官方帮助](https://help.line.me/line/?contentId=20020931)确认其最新 APK 链接入口。 | 当前 HTML 正文无 `apk`，未获得实际文件 href；故 URL、版本、长度、跳转域均未锁。搜索索引曾显示 APK 菜单，但当前响应不能据此推断文件。 | 使用真实移动页面/交互 DOM 提取 APK 按钮目标，随后 HEAD 锁响应；必要时咨询发布者。 |
| Epic Games Store | [官方移动页](https://store.epicgames.com/mobile/epic-games-app/)写明 Android 全球直接从 Epic 安装；[官方安装说明](https://www.epicgames.com/help/c-32735058/c-34235392/a20529412?lang=en-US)说明站点安装步骤。 | 本机对 `store.epicgames.com/mobile/android` 和官方帮助页实测 403，且可抓页面未给固定 APK href；URL、版本、长度、最终域均未锁。另需避免混淆 Epic Games companion app 与 Epic Games **Store** app。 | 在可访问地区的官方移动浏览器交互“Install on Android”，抓按钮发起的 HTTPS 跳转，再仅以 HEAD 审核最终官方交付域。 |

此轮只有 Zoom **历史版**形成 URL/跳转/声明长度的条件性元数据锁。没有任何一个当前版本完成全字段锁定，也没有 APK 原包接受、静态扫描、黑盒资格或冷启动结果。`Content-Length` 是服务器 HEAD 声明，须在实际下载时按字节数、SHA、签名和包身份复核。
