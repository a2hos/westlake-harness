# 南海 plus 当前环境 — Bionic 主线

唯一活动定义为下方 JSON 块。当前目标 OH7.0.0.39 / android-16.0.0_r4 / ARM64 / App 单 Bionic；OH 服务仍可在独立 Musl 进程运行。构建、测试和 App 运行均禁止容器、OCI 镜像及容器内进程；历史 Docker 收据只作失败证据。通过 `python3 -B scripts/nanhai_plus_env.py --run <command>` 注入 NANHAI_*，不从旧 shell 继承配置。

RUNTIME/HARNESS/OUT/TMP/STAGING 属于本项目 Bionic 工作树；该工作树初始 harness HEAD 是历史 OH6.1 来源，不代表已有 AOSP16 Bionic 实现。NANHAI_MUSL_* 是保留的历史输入/输出，不是新包默认源。通用 NANHAI_CLANG/CLANGXX 已撤销：OH 编译器只作为 NANHAI_OH_CLANG/CLANGXX 用于服务域；Bionic 工具链、sysroot、CRT、实际 argv 逐包锁定，未绑定前 BUILD_READY=false。

版本化源码从 NANHAI_SOURCE_POOL_ROOT 查共享 AGENTS/README/SOURCES，按精确版本与完整性复用，仅补缺项。登记的 AOSP 输入可能是选定子集；目录存在不证明完整树。Bio3/BridgeAOSPV16 根只读参考，不写其文件/会话/进程/设备。

项目内声明软链接到登记共享根按合法只读输入处理；不能借其写共享源码或输出。任何实际构建必须用独立工作树、OUT_DIR/TMPDIR/staging，真实 argv 证明隔离。设备命令每次读 NANHAI_DEVICE_ACCESS_POLICY，当前最多 2 个设备槽、6 个构建子作业。

切换前全部环境文档、版本锁和控制文件保存在 docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/root-transition-v1/before；封存证据与旧 Musl 锁不改。

<!-- NANHAI_ENV_BEGIN -->
```json
{
  "schema": 1,
  "paths": {
    "NANHAI_PROJECT_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye",
    "NANHAI_SOURCE_POOL_ROOT": "/opt/19.SourceCode",
    "NANHAI_R4_WORKSPACE_ROOT": "/opt/19.SourceCode/AOSP-16.0.0_r4",
    "NANHAI_AOSP_SOURCE_ROOT": "/opt/19.SourceCode/AOSP-16.0.0_r4/android-source",
    "NANHAI_ART_SOURCE_ROOT": "/opt/19.SourceCode/AOSP-16.0.0_r4/art",
    "NANHAI_RUST_HOST_ROOT": "/opt/19.SourceCode/Rust-1.88.0-Android-13951379/host/darwin-x86/1.88.0",
    "NANHAI_RUSTC": "/opt/19.SourceCode/Rust-1.88.0-Android-13951379/host/darwin-x86/1.88.0/bin/rustc",
    "NANHAI_CARGO": "/opt/19.SourceCode/Rust-1.88.0-Android-13951379/host/darwin-x86/1.88.0/bin/cargo",
    "NANHAI_RUST_SOURCE_ROOT": "/opt/19.SourceCode/Rust-1.88.0-Android-13951379/stdlib-source/linux-x86/1.88.0/lib/rustlib/src/rust",
    "NANHAI_RUST_CRATES_ROOT": "/opt/19.SourceCode/AOSP-16.0.0_r4/android-source/rust-crates",
    "NANHAI_RUST_CXX_ROOT": "/opt/19.SourceCode/AOSP-16.0.0_r4/android-source/rust-cxx",
    "NANHAI_OH_SOURCE_ROOT": "/opt/19.SourceCode/OpenHarmony-7.0.0.39",
    "NANHAI_OH_SDK_ROOT": "/opt/19.SourceCode/OpenHarmony-SDK-26.0.0.39-mac-arm64/extracted/native",
    "NANHAI_OH_SYSROOT": "/opt/19.SourceCode/OpenHarmony-SDK-26.0.0.39-mac-arm64/extracted/native/sysroot",
    "NANHAI_OH_CXX_INCLUDE_ROOT": "/opt/19.SourceCode/OpenHarmony-SDK-26.0.0.39-mac-arm64/extracted/native/llvm/include/libcxx-ohos/include/c++/v1",
    "NANHAI_HOST_TOOLS_ROOT": "/opt/19.SourceCode/AOSP-16.0.0_r4/host-tools",
    "NANHAI_EVIDENCE_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/docs/nanhai-plus/evidence",
    "NANHAI_HOST_CC": "/usr/bin/cc",
    "NANHAI_FLAGS_SOURCE_ROOT": "/opt/19.SourceCode/AOSP-16.0.0_r4/android-source/server-configurable-flags",
    "NANHAI_MINIKIN_SOURCE_ROOT": "/opt/19.SourceCode/AOSP-16.0.0_r4/android-source/minikin",
    "NANHAI_ICU_SOURCE_ROOT": "/opt/19.SourceCode/AOSP-16.0.0_r4/android-source/icu",
    "NANHAI_LOGGING_SOURCE_ROOT": "/opt/19.SourceCode/AOSP-16.0.0_r4/android-source/logging",
    "NANHAI_R4_CLANG_CANDIDATE_ROOT": "/opt/19.SourceCode/AOSP-16.0.0_r4/host-tools/clang-r563880c-linux-x86",
    "NANHAI_TINYXML2_SOURCE_ROOT": "/opt/19.SourceCode/AOSP-16.0.0_r4/reference-dependencies/tinyxml2",
    "NANHAI_PALETTE_REFERENCE_ROOT": "/opt/19.SourceCode/WestLake-Harness-5d09511c063e/source/bms/src/adapter/framework/art-palette-oh",
    "NANHAI_N1_REFERENCE_ROOT": "/opt/19.SourceCode/WestLake-Harness-0b8588216ca4/source",
    "NANHAI_CONTROL_SOURCE_ROOT": "/opt/19.SourceCode/Octos-2.0.2-g7-1b6bb8e8b19b/worktrees/opaleye-turn-stop",
    "NANHAI_CONTROL_SOURCE_LINK": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/backend-source",
    "NANHAI_CONTROL_BUILD_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/backend-build-g7",
    "NANHAI_CONTROL_TMP_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/backend-build-tmp",
    "NANHAI_CONTROL_CARGO": "/opt/homebrew/bin/cargo",
    "NANHAI_CONTROL_CARGO_HOME": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/backend-cargo-home",
    "NANHAI_CONTROL_BACKEND": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/bin/octos-g116-hydrate-a079fec99fc0c8f7",
    "NANHAI_HDC": "/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/toolchains/hdc",
    "NANHAI_DEVICE_LEASE_ROOT": "/opt/16.YueAPP/.control/devices/leases",
    "NANHAI_DEVICE_ACCESS_POLICY": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/state/device_access_policy.json",
    "NANHAI_APPDATA_PYTHON": "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9",
    "NANHAI_GZ02_TOOLCHAIN_CANDIDATE_ROOT": "/opt/19.SourceCode/OpenHarmony-Clang-15.0.4-02fbe8-linux-x86_64-20260908/extracted",
    "NANHAI_GZ02_PRODUCT_INPUT_CANDIDATE_ROOT": "/opt/19.SourceCode/OpenHarmony-7.0.0.39-wukong100-20261003-GZ02",
    "NANHAI_GZ02_PRODUCT_INPUT_ARCHIVE": "/opt/19.SourceCode/OpenHarmony-7.0.0.39-wukong100-20261003-GZ02/downloads/gz02-selected-product-inputs.tar.gz",
    "NANHAI_MUSL_RUNTIME_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/musl-oh7-pilot",
    "NANHAI_MUSL_HARNESS_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/musl-oh7-pilot/source",
    "NANHAI_MUSL_INPUTS_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/musl-oh7-pilot/inputs-view",
    "NANHAI_MUSL_INPUTS_LINK": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/musl-oh7-pilot/inputs",
    "NANHAI_MUSL_ADAPTER_SOURCE_ROOT": "/opt/19.SourceCode/WestLake-22b945321929/worktrees/oh39-r4-musl",
    "NANHAI_MUSL_MANIFEST_ROOT": "/opt/19.SourceCode/WestLake-Manifest-5057daae7450/worktrees/oh39-r4-musl",
    "NANHAI_MUSL_TARGET_LOCK_ROOT": "/opt/19.SourceCode/WestLake-Manifest-5057daae7450/worktrees/oh39-r4-musl/targets/oh39-r4-musl-arm64",
    "NANHAI_MUSL_OUT_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/musl-oh7-pilot/out",
    "NANHAI_MUSL_DEPENDENCY_OUT_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/musl-oh7-pilot/out/unified-dependencies-m07-33",
    "NANHAI_MUSL_CXX_HOST_INPUT_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/musl-oh7-pilot/inputs-view/cxxbridge-host-1.0.160",
    "NANHAI_MUSL_CXXBRIDGE": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/musl-oh7-pilot/out/unified-dependencies-m07-33/cxxbridge-host-g15/target/x86_64-apple-darwin/release/cxxbridge",
    "NANHAI_MUSL_RUST_HOST_LINKER": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/musl-oh7-pilot/out/unified-dependencies-m07-33/cxxbridge-host-g15/cc-native-arm64",
    "NANHAI_MUSL_OH_CXX_COMPAT_INCLUDE_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/musl-oh7-pilot/out/unified-dependencies-m07-33/cxx-compat-g22/inputs/overlay",
    "NANHAI_MUSL_CXX_GENERATED_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/musl-oh7-pilot/out/unified-dependencies-m07-33/cxx-ffi-g16",
    "NANHAI_MUSL_MINIKIN_BUILD_ROOT": "/opt/19.SourceCode/AOSP-16.0.0_r4/worktrees/opaleye-minikin-oh39-r4-musl",
    "NANHAI_MUSL_ART_BUILD_ROOT": "/opt/19.SourceCode/WestLake-ART-Build-9acbaec8c3bd/worktrees/oh39-r4-musl",
    "NANHAI_MUSL_PALETTE_WORKTREE_ROOT": "/opt/19.SourceCode/WestLake-Harness-5d09511c063e/worktrees/oh39-r4-musl",
    "NANHAI_MUSL_SIGCHAIN_WORKTREE_ROOT": "/opt/19.SourceCode/AOSP-16.0.0_r4/worktrees/opaleye-sigchain-oh39-r4-musl",
    "NANHAI_MUSL_N1_HOST_TEST_ROOT": "/opt/19.SourceCode/WestLake-Harness-0b8588216ca4/worktrees/opaleye-anl-host-fixture",
    "NANHAI_MUSL_GZ02_TOOLCHAIN_INPUT_LINK": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/musl-oh7-pilot/inputs-view/gz02-oh39-02fbe8-toolchain-candidate",
    "NANHAI_MUSL_GZ02_PRODUCT_INPUT_LINK": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/musl-oh7-pilot/inputs-view/gz02-oh39-product-input-candidate",
    "NANHAI_OH_CLANG": "/opt/19.SourceCode/OpenHarmony-SDK-26.0.0.39-mac-arm64/extracted/native/llvm/bin/clang",
    "NANHAI_OH_CLANGXX": "/opt/19.SourceCode/OpenHarmony-SDK-26.0.0.39-mac-arm64/extracted/native/llvm/bin/clang++",
    "NANHAI_RUNTIME_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/bionic-oh7-aosp16",
    "NANHAI_HARNESS_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/bionic-oh7-aosp16/source",
    "NANHAI_INPUTS_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/bionic-oh7-aosp16/inputs-view",
    "NANHAI_OUT_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/bionic-oh7-aosp16/out",
    "NANHAI_TMP_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/bionic-oh7-aosp16/tmp",
    "NANHAI_STAGING_ROOT": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/bionic-oh7-aosp16/staging",
    "NANHAI_INPUTS_LINK": "/Users/alexyang/orca/workspaces/westlake-harness/opaleye/.nanhai-plus-runtime/bionic-oh7-aosp16/inputs",
    "NANHAI_BIO3_REFERENCE_ROOT": "/opt/adapterBio3",
    "NANHAI_BRIDGE16_REFERENCE_ROOT": "/opt/BridgeAOSPV16",
    "NANHAI_CURL": "/usr/bin/curl",
    "NANHAI_PYTHON": "/usr/local/bin/python3"
  },
  "values": {
    "NANHAI_AOSP_TAG": "android-16.0.0_r4",
    "NANHAI_OH_VERSION": "7.0.0.39",
    "NANHAI_ARCH": "arm64",
    "NANHAI_LIBC": "bionic",
    "NANHAI_RUST_TARGET": "aarch64-linux-android",
    "NANHAI_DOWNLOAD_JOBS": "3",
    "NANHAI_BUILD_JOBS": "6",
    "NANHAI_CONTAINER_POLICY": "forbidden",
    "NANHAI_BUILD_EXECUTION_MODE": "host-native",
    "NANHAI_CONTROL_SESSION_MAX_BYTES": "1073741824",
    "NANHAI_A86_DEVICE_SERIAL": "5ce24a7800000000000000000923012c",
    "NANHAI_DEVICE_STAGE_ROOT": "/data/local/tmp/nanhai-plus-a86",
    "NANHAI_A86_BUILD_PARALLEL": "6",
    "NANHAI_A86_DEVICE_PARALLEL": "2",
    "NANHAI_GZ02_BUILD_HOST": "gz02",
    "NANHAI_GZ02_AOSP_SOURCE_ROOT": "/opt/19.SourceCode/AOSP-16.0.0_r4/android-source",
    "NANHAI_GZ02_SOONG_WORKTREE": "/opt/19.SourceCode/AOSP-16.0.0_r4/worktrees/opaleye-soong-no-container",
    "NANHAI_GZ02_NATIVE_PROJECT_ROOT": "/data/source/.nanhai-plus-opaleye-native-v7",
    "NANHAI_GZ02_NATIVE_SOURCE_VIEW": "/data/source/.nanhai-plus-opaleye-native-v7/source-view",
    "NANHAI_GZ02_SOONG_UI": "/data/source/.nanhai-plus-opaleye-native-v7/out/soong-ui-v1/soong_ui",
    "NANHAI_GZ02_OH_SOURCE_ROOT": "/data/openharmony-26.0.0.39-wukong100-source",
    "NANHAI_GZ02_OH_PRODUCT_OUT": "/data/oh61/build/oh7-release-wukong100/out/wukong100",
    "NANHAI_TARGET_ID": "oh7.0.0.39-aosp16r4-arm64-bionic",
    "NANHAI_TARGET_REVISION": "bionic-mainline-v1",
    "NANHAI_BIONIC_BUILD_READY": "false",
    "NANHAI_METADATA_HTTPS_PROXY": "http://127.0.0.1:7897"
  },
  "links": [
    {
      "link": "NANHAI_MUSL_INPUTS_LINK",
      "target": "NANHAI_MUSL_INPUTS_ROOT"
    },
    {
      "link": "NANHAI_CONTROL_SOURCE_LINK",
      "target": "NANHAI_CONTROL_SOURCE_ROOT"
    },
    {
      "link": "NANHAI_MUSL_GZ02_TOOLCHAIN_INPUT_LINK",
      "target": "NANHAI_GZ02_TOOLCHAIN_CANDIDATE_ROOT"
    },
    {
      "link": "NANHAI_MUSL_GZ02_PRODUCT_INPUT_LINK",
      "target": "NANHAI_GZ02_PRODUCT_INPUT_CANDIDATE_ROOT"
    },
    {
      "link": "NANHAI_INPUTS_LINK",
      "target": "NANHAI_INPUTS_ROOT"
    }
  ]
}
```
<!-- NANHAI_ENV_END -->

`--check` 只核路径和链接，不能替代构建/设备准入；新增 Bionic 包需绑定环境配置 SHA 和目标版本。
