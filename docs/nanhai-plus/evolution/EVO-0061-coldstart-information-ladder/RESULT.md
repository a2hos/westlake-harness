# EVO61 — first cold-start information ladder

## Problem and one proposed change

After HelloWorld reaches a verified cold-start floor, choose the first real APKs by increasing *packaged* ARM64 native-library exposure: Privacy Browser (0) → PContacts (1) → FairScan (11). Defer PUBG (40 ARM64 ELF, 1.27 GB) from this first diagnostic trio. This is a proposed **test order**, not an APK/runtime admission or evidence of Java-only execution. A zero-ELF APK can still use framework/system native code or load code dynamically.

## Frozen input and bounded pilot

`INPUTS.json` freezes SHA-256 of root-limited RAW/STATIC admission receipts and candidate static receipts for four distinct package names. Input manifest SHA-256: `74cfff80960108ce0e1824c4e0cc8e09cd4ae06e85230b8904833e84ac040efd`. `pilot.py` verifies every frozen receipt hash, exact APK identity across receipts, and root-limited RAW/STATIC decisions. It reads through `NANHAI_PROJECT_ROOT` supplied by `scripts/nanhai_plus_env.py`.

Commands, from project root (outputs are this directory):

```sh
python3 -B scripts/nanhai_plus_env.py --run python3 -B docs/nanhai-plus/evolution/EVO-0061-coldstart-information-ladder/pilot.py > docs/nanhai-plus/evolution/EVO-0061-coldstart-information-ladder/POSITIVE.json
# rc 0
python3 -B scripts/nanhai_plus_env.py --run python3 -B docs/nanhai-plus/evolution/EVO-0061-coldstart-information-ladder/pilot.py --counterexample > docs/nanhai-plus/evolution/EVO-0061-coldstart-information-ladder/COUNTEREXAMPLE.json
# rc 2
```

The positive run gives `GO_CANDIDATE_ORDER_ONLY`: four receipt identities matched; packaged true ARM64 ELF counts were 0/1/11/40, semantic DEX counts 1/1/1/3, and all four had root-limited RAW and STATIC admissions. The negative run mutates only the in-memory Privacy Browser ELF count from 0 to 1 and gives `NO_GO_ORDER_PREMISE`, demonstrating that the sentinel/strict-gradient premise is actually checked. Output SHA-256: `POSITIVE.json` `a3ed8761b33276e2c96b56d33898d614480704e8c8b6aa65281b3a07a9826c05`; `COUNTEREXAMPLE.json` `5d923e180514159982ed7aa14001aeea140dfd16231627539e875f9acb9bd736`. Script SHA-256: `97d02edc12d280764e7e7f45c40c929130dedff1d3033476e37f2600534e4b51`.

## Promotion gate and limit

Promote this ordering to the run queue only after the authorized HelloWorld floor is actually established and each APK's cold launch has a separate, same-device, fresh runtime receipt. Compare the first failing stage for the 0- and 1-ELF packages before attributing any failure to native packaging; if both fail at the same earlier stage, the gradient has provided no native-stage discrimination and should be dropped. This pilot issued **zero device, container, or Bridge commands** and observed **zero cold starts**. It did not change the 200-APK count, root admissions, or project control documents.
