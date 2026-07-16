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
node generate_aes_key.js myPartition myAesKey 256
node sign_using_rsa_sha256.js myPartition
node encrypt_using_aes-gcm.js myPartition
node derive_using_sha256.js myPartition
node wrap_secret_key_using_aes_kw.js myPartition
node create_known_keys.js myPartition
node pqc_mechanism_probe.js myPartition
```

## Coverage

| Area | Status |
|------|--------|
| Python PKCS#11 set | Full 1:1 |
| C/JSP encrypt / sign / MAC / digest / wrap (common mechs) | Covered (incl. AES_KW, AES_CBC_PAD, DES3, RSA X.509 / X9.31) |
| Object mgmt (create/find/list/get/set/copy/destroy) | Covered |
| Import known secret key (`CreateKnownKeys`) | `create_known_keys.js` |
| Key derivation (SHA256_KEY_DERIVATION, ECDH) | Covered |
| Crypto User login | `login_crypto_user.js` (needs CU PIN on partition) |
| Seed RNG | `seed_random.js` (may be unsupported on some Cloud HSM images) |
| Private-key wrap (AES / AES_KWP) | Present; needs partition policy 1 |
| **PQC** (ML-DSA / ML-KEM / HSS) | Probe only — deferred |
| **Luna FM** | Not ported |
| Java LunaKeyStore / LunaProvider-only | N/A (use PKCS#11 find/login) |
| SafeNet vendor extensions (SIM, Remote PED, CA_*, per-key auth, partition policies API) | Not ported (outside standard Cryptoki via graphene) |
| Multi-thread signing / usage-limit demos | Not ported |
| SHA3 / SHAKE / Ed25519 / PBKDF2 / NIST PRF / DSA domain params | Not ported (mech often absent, or needs custom param marshalling) |

These samples are for learning and testing only — not production use.

PIN prompts mask input when run on a TTY (or set `LUNA_PIN` / `LUNA_CU_PIN`).
