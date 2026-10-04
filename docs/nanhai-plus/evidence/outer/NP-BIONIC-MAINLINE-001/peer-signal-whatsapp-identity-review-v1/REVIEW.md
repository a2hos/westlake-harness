# Independent identity review: Signal and WhatsApp existing APKs

This review uses existing project staging bytes only. It performed no download and did not modify the APKs, canonical counts, device, container, Bridge, or historical receipts.

I independently ran the pinned local `aapt2 dump badging` and `apksigner verify --verbose --print-certs` against the existing read-only Signal alias and WhatsApp APK, then enumerated ZIP members, CRC, duplicate names, manifest and DEX counts. Output hashes and machine facts are in `IDENTITY-REVIEW.json` (SHA-256 `b1a096d800e338c41f71ca203162d31a03230273cdf07ea58627a64d29490bd0`).

| Existing APK | SHA-256 / bytes | Package, versionCode, versionName | Signer certificate SHA-256 | ZIP facts |
| --- | --- | --- | --- | --- |
| `staging/g324-signal-v2/Signal.apk` | `9fca2a1cd46ad805bd12d7bcc3930cc9388bffd5a1d01b0422c6149f1b702122` / 114,758,484 | `org.thoughtcrime.securesms` / `175901` / `8.29.3` | `4be4f6cd5be844083e900279dc822af65a547fecc26aba7ff1f5203a45518cd8` (API 33+); `29f34e5f27f211b424bc5bf9d67162c0eafba2da35af35c16416fc446276ba26` (API 24–32) | 4,185 entries, CRC clean, zero duplicate names, one manifest, six root DEX, 48 `.so` |
| `staging/g312-whatsapp-official-v1/WhatsApp.apk` | `c4260c7c569c19267fd33ee33b6241fadbee55e3bcfceb3ee151012801368dbb` / 148,660,262 | `com.whatsapp` / `263907133` / `2.26.39.71` | `fb920d381bee1b2093f27dc8f13d994da629dc91887d0529b35c9a2dc4f4a6c2` (API 33+); `3987d043d10aefaf5a8710b3671418fe57e0e19b653c9df82558feb5ffce5d44` (API 24–32) | 15,156 entries, CRC clean, zero duplicate names, one manifest, twelve root DEX, 12 `.so` |

Signal's historical v1 raw file had a suffix-driven metadata rc2; the existing `.apk` alias was separately admitted for four-phase host static only. The independent package and signer results match the v2 static admission facts; this review leaves the v1 failure immutable.

WhatsApp's historical raw supplement was accepted for host static only. The three version labels remain separate: official download page label `2.26.32.84`, historical registered version `2.26.37.73`, and package manifest version `2.26.39.71` (code `263907133`). The raw supplement's signature/manifest gap was explicitly retained; current independent verification closes identity for this existing APK but does not retroactively prove page-version equivalence or blackbox qualification.

The matching historical receipts are:

- Signal v2 root static admission: `g324-signal-four-static-candidate-v2/root-static-admission-v1/ROOT-STATIC-ADMISSION.json`, raw SHA binding `9fca2a1c…`; four phases rc0, 6 DEX and 12 true ARM64 ELF, static-only.
- WhatsApp raw supplement: `mainstream-whatsapp-official-supplement-v1/root-intake-v1/ROOT-ACCEPTANCE.json`, raw SHA `c4260c7c…`; host static admission `raw112-static111-whatsapp-four-static-v1/ROOT-STATIC-ADMISSION.json`, package `com.whatsapp` version `2.26.39.71`, 12 DEX and 3 true ARM64 ELF, with page mismatch retained.

No startup, installation, runtime compatibility or blackbox qualification is claimed. No authoritative count changed.
