# Opera official APK intake candidate

This is a host-only candidate, not root admission, device testing, or startup credit. Three distinct packages were downloaded once each from links on Opera's official [download page](https://www.opera.com/download). The bytes are retained only in project-local `NANHAI_STAGING_ROOT`; do not commit or redistribute the APKs. No container, namespace, or device command ran.

| App | Package / version | APK SHA-256 | Size | ABI | Result |
| --- | --- | --- | ---: | --- | --- |
| Opera Browser | `com.opera.browser` 102.3.5206.90530 | `fd2b2e3578d7c6e3fdb9f0f9b932b315d9e2612bc68f073169f422c6ed5dcce6` | 279570110 | arm64-v8a only | Candidate |
| Opera GX | `com.opera.gx` 3.3.13 | `22f2921d3a91e94f3689f104a52d502ae6f5ad46e32cedf67e98b760be9c9503` | 64107242 | arm64-v8a, armeabi-v7a, x86, x86_64 | Candidate |
| Opera Mini | `com.opera.mini.native` 99.6.2254.2363 | `b7a9aee039fec78693eac2c21a31df82703d9be50dfae7ca59ca41a51b46fe64` | 46507432 | armeabi-v7a only | Reject from current ARM64 intake |

All three downloads returned curl rc0, HTTP 200, TLS verify 0, matched the prior HEAD size, passed full ZIP CRC and aapt2 package extraction, and passed `apksigner verify`. Browser and GX have ARM64 native libraries; Mini does not. Browser/GX used APK v3 signatures. Exact receipt paths under `NANHAI_STAGING_ROOT` are `apk-opera-official-v1/CANDIDATE.json`, `apk-opera-gx-official-v1/CANDIDATE.json`, and `apk-opera-mini-official-v1/CANDIDATE.json`; their SHA-256 values are respectively `01d15303d85dcf3c77750320ccd60032c5aecaae7c6886696e249f6b79d2742b`, `f0ac49ff2345f5906dc34fa9d57a8492b8bf9f6e8b3dd418eb577f45cfec90a1`, and `f49ea93962b79c4294e78a96e41169eb081379803113647706fad373d78bf1ee`.

For qualification review: [Google Play](https://play.google.com/store/apps/details?id=com.opera.browser) associates Browser's package with Opera and currently shows 500M+ downloads; Opera's [mobile EULA](https://www.opera.com/legal/eula-mobile) describes its mobile application as licensed executable code, with separately licensed open-source components. Opera [reports international mobile usage](https://press.opera.com/2026/07/14/opera-mobile-growth-us-uk/). These support a Browser blackbox/mainstream candidate, but root should independently check package identity, published channel, current market data, and GX's separate reach before any blackbox count change. Signer certificate binding to an Opera-published digest has not been established. Neither package has a complete static inventory or cold start.
