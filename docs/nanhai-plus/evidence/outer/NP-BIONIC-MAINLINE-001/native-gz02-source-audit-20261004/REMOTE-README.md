# Shared source pool on gz02

Follow `AGENTS.md` and `SOURCES.json`. The canonical AOSP16 R4 entry is a read-only alias to the existing `/data/source/aosp-16.0.0-r4` checkout. The 42 stock roots and four key input roots were checked for exact tag HEAD, tracked cleanliness, and missing tracked paths; this is not a full byte audit or build pass. The project Soong patch lives in `AOSP-16.0.0_r4/worktrees/opaleye-soong-no-container`; outputs and control files live separately under `/data/source/.nanhai-plus-opaleye-native`. The UI patch has not yet been built or run.
