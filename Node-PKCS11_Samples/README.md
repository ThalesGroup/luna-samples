# Node-PKCS11 Samples for Luna HSMs

Node.js ports of the `Python-PKCS11_Samples` from [ThalesGroup/luna-samples](https://github.com/ThalesGroup/luna-samples), using [`graphene-pk11`](https://www.npmjs.com/package/graphene-pk11), plus additional coverage of common **C** / **LunaJSP** PKCS#11 actions.

## Requirements

- Node.js 18+
- Luna Client installed and configured
- `npm install` in this directory

## Environment

```powershell
$env:ChrystokiConfigurationPath = "C:\Program Files\SafeNet\LunaClient"
$env:P11_LIB = "C:\Program Files\SafeNet\LunaClient\cryptoki.dll"
$env:LUNA_PIN = "<crypto-officer-pin>"
$env:LUNA_CU_PIN = "<crypto-user-pin>"   # only for login_crypto_user.js
$env:SAMPLE_PLAINTEXT = "hello luna"     # optional for encrypt/sign demos
```

## Examples

```powershell
node enumerate_slots.js
node login_logout.js myPartition
node digest_using_sha3_256.js myPartition
node digest_using_shake_256.js myPartition 50
node sign_using_eddsa.js myPartition
node usage_limit_demo.js myPartition 3
node multi_thread_signing.js myPartition 4 10
node pqc_mechanism_probe.js myPartition
```

## Coverage

| Area | Status |
|------|--------|
| Python PKCS#11 set | Full 1:1 |
| C/JSP encrypt / sign / MAC / digest / wrap (common mechs) | Covered |
| SHA3-256 / SHAKE-256 | Covered (`digest_using_sha3_256.js`, `digest_using_shake_256.js`) |
| Ed25519 (Edwards / EDDSA) | Covered (`generate_eddsa_keypair.js`, `sign_using_eddsa.js`) |
| Usage limit (`CKA_USAGE_LIMIT`) | Covered (`usage_limit_demo.js`) |
| Multi-thread signing | Covered (`multi_thread_signing.js`) |
| Object mgmt (create/find/list/get/set/copy/destroy) | Covered |
| Import known secret key (`CreateKnownKeys`) | `create_known_keys.js` |
| Key derivation (SHA256, ECDH) | Covered |
| PBKDF2 / NIST PRF KDF | Covered (`derive_using_pbkd2.js`, `derive_using_nist_prf_kdf.js`) |
| DSA | Covered (`generate_dsa_keypair.js`, DSA-2048 domain params + sign/verify) |
| Crypto User login | `login_crypto_user.js` |
| Seed RNG | `seed_random.js` |
| Private-key wrap (AES / AES_KWP) | Present; needs partition policy 1 |
| **PQC** (ML-DSA / ML-KEM / HSS) | Probe only — deferred |
| **Luna FM** | Not ported |
| Java LunaKeyStore / LunaProvider-only | N/A (use PKCS#11 find/login) |
| SafeNet vendor extensions (SIM, Remote PED, CA_*, per-key auth) | Not ported |

These samples are for learning and testing only — not production use.

PIN prompts mask input when run on a TTY (or set `LUNA_PIN` / `LUNA_CU_PIN`).
Exit code `2` means the sample ran but the HSM rejected the mechanism (policy / FIPS / firmware), not a script crash.
