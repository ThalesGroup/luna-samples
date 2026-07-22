# Node-PKCS11 Samples for Luna HSMs

Node.js ports of the `Python-PKCS11_Samples` from [ThalesGroup/luna-samples](https://github.com/ThalesGroup/luna-samples), using [`graphene-pk11`](https://www.npmjs.com/package/graphene-pk11), plus additional coverage of common **C** / **LunaJSP** PKCS#11 actions.

## Requirements

- Node.js 18+
- Luna Client or DPoD client installed and configured
- `npm install` in this directory

## Environment

**Windows (PowerShell):**

```powershell
$env:ChrystokiConfigurationPath = "C:\Program Files\SafeNet\LunaClient"
$env:P11_LIB = "C:\Program Files\SafeNet\LunaClient\cryptoki.dll"
$env:LUNA_PIN = "<crypto-officer-pin>"
$env:LUNA_CU_PIN = "<crypto-user-pin>"   # only for login_crypto_user.js
$env:SAMPLE_PLAINTEXT = "hello luna"     # optional for encrypt/sign demos
```

**Linux (bash)** — on-prem Luna Client defaults to
`/usr/safenet/lunaclient/lib/libCryptoki2_64.so`. For a DPoD min-client
extracted from `cvclient-min.tar`:

```bash
source /path/to/dpod-client/setenv   # sets ChrystokiConfigurationPath
export P11_LIB=/path/to/dpod-client/libs/64/libCryptoki2.so
export LUNA_PIN="<crypto-officer-pin>"
export LUNA_CU_PIN="<crypto-user-pin>"
export SAMPLE_PLAINTEXT="hello luna"
```

Samples that pack PKCS#11 structs (`PBKD2`, NIST PRF KDF, `CK_ULONG`
attribute values) select Windows `#pragma pack(1)` / 32-bit `CK_ULONG` vs
Linux natural alignment / 64-bit `CK_ULONG` automatically.

## Examples

```powershell
node enumerate_slots.js
node login_logout.js myPartition
node digest_using_sha3_256.js myPartition
node digest_using_shake_256.js myPartition 50
node sign_using_eddsa.js myPartition
node usage_limit_demo.js myPartition 3
node multi_thread_signing.js myPartition 4 10
node multi_thread_keygen.js myPartition --compare 5
node pqc_mechanism_probe.js myPartition
node pqc_mldsa_sign_verify.js myPartition
```

## PQC samples (raw `pkcs11js`)

Ports of `C_Samples/pqc` + `LunaJSP_Samples/pqc`. Requires client **10.9+** and firmware with the mechanism (ML-DSA/ML-KEM: **7.9+**, HSS: **7.8.9+**). Session objects only unless noted.

| Script | C / JSP counterpart |
|--------|---------------------|
| `pqc_mechanism_probe.js` | (inventory) |
| `pqc_mldsa_generate_keypair.js` | `CKM_ML_DSA_KEY_PAIR_GEN_demo` / `GenerateMLDSAKeyPair` |
| `pqc_mldsa_sign_verify.js` | `CKM_ML_DSA_Sign_Verify_demo` / `SignUsing_MLDSA` |
| `pqc_hash_mldsa_sign_verify.js` | `CKM_HASH_ML_DSA_Sign_Verify_demo` / `SignUsing_HASH_MLDSA` |
| `pqc_hash_mldsa_sha3_512_sign_verify.js` | `CKM_HASH_ML_DSA_SHA3_512_*` / `SignUsing_MLDSAwithSHA3_*` |
| `pqc_extmu_mldsa_sign_verify.js` | `CKM_EXTMU_ML_DSA_*` / `SignUsing_EXTMU_MLDSA` |
| `pqc_mlkem_generate_keypair.js` | `CKM_ML_KEM_KEY_PAIR_GEN_demo` / `GenerateMLKEMKeyPair` |
| `pqc_mlkem_encapsulate_decapsulate.js` | `CKM_ML_KEM_Encapsulate_*` / `KeyEncapsulation_MLKEM` (via `CA_EncapsulateKey`) |
| `pqc_hss_generate_keypair.js` | `CKM_HSS_KEY_PAIR_GEN_demo` |
| `pqc_hss_sign_verify.js` | `CKM_HSS_sign` + `CKM_HSS_verify` (combined) |
| `pqc_wrap_unwrap_private_key.js` | `Wrap_PQC_*` + `Unwrap_PQC_*` (combined; needs wrap policy) |

```powershell
node pqc_mldsa_sign_verify.js myPartition
node pqc_mlkem_encapsulate_decapsulate.js myPartition 768
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
| Multi-thread keygen (+ compare) | Covered (`multi_thread_keygen.js`) |
| Object mgmt (create/find/list/get/set/copy/destroy) | Covered |
| Import known secret key (`CreateKnownKeys`) | `create_known_keys.js` |
| Key derivation (SHA256, ECDH) | Covered |
| PBKDF2 / NIST PRF KDF | Covered (`derive_using_pbkd2.js`, `derive_using_nist_prf_kdf.js`) |
| DSA | Covered (`generate_dsa_keypair.js`, DSA-2048 domain params + sign/verify) |
| Crypto User login | `login_crypto_user.js` |
| Seed RNG | `seed_random.js` |
| Private-key wrap (AES / AES_KWP) | Present; needs partition policy 1 |
| **PQC** (ML-DSA / ML-KEM / HSS / wrap) | Covered via raw `pkcs11js` (+ `CA_*` for ML-KEM encaps) |
| **Luna FM** | Not ported |
| Java LunaKeyStore / LunaProvider-only | N/A (use PKCS#11 find/login) |
| SafeNet vendor extensions (SIM, Remote PED, per-key auth) | Not ported (except PQC `CA_EncapsulateKey` / `CA_DecapsulateKey`) |

These samples are for learning and testing only — not production use.

PIN prompts mask input when run on a TTY (or set `LUNA_PIN` / `LUNA_CU_PIN`).
Exit code `2` means the sample ran but the HSM rejected the mechanism (policy / FIPS / firmware), not a script crash.
