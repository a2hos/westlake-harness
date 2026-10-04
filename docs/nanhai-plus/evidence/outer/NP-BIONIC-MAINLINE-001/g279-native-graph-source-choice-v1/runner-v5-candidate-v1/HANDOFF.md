# G279 runner v5 静态候选

本版只接收 G279 受控 UI smoke 的新增事实：同一 cwd、相同 argv 除 `GOROOT` 外不变时，不设 `GOROOT` 的 `soong_ui --help` 在 microfactory package init 返回 rc2；显式设为 `${NANHAI_GZ02_AOSP_SOURCE_ROOT}/prebuilts/go/linux-x86` 后到达预期 getCommand 拒绝，返回 rc1。根受控对照与两份原始收据的 SHA 已固定在 `STATIC-CANDIDATE.json`。它只证明宿主 UI 前置路径，未执行 Soong 图。

v5 的未启用执行路径现在显式传递 GOROOT，以登记的源码别名作为 cwd，并在前置身份检查中核 Go `VERSION` 文件内容、35 字节和 SHA，以及 `bin/go` 的 14,314,606 字节和 SHA。`GO-IDENTITY.json` 是对 gz02 两个文件的独立只读回读，SSH outer rc 与远端 rc 均为 0；它不是 EVO19 的构图放行收据。

沿 v4 独审修正，终态只向项目控制目录写一份不可覆盖的预控制 `RESULT.json`，在最终返回码确定后写入；写失败返回 7，不能形成成功声明。SIGTERM/SIGINT 清理仍只有本地 mock 夹具，真实脱离后代没有证明。生成 Ninja 的词法检查只标记线索，始终不授权目标 Ninja 动作。`--run` 硬返回 3；静态检查与八项本地夹具 rc0。完整 EVO19 单收据身份门、原 owner ACK、远端守卫及 graph/target/device 验证仍缺失。
