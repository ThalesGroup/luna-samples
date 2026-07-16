# Node-PKCS11 Samples for Luna HSMs

Node.js ports of the `Python-PKCS11_Samples` from [ThalesGroup/luna-samples](https://github.com/ThalesGroup/luna-samples), using [`graphene-pk11`](https://www.npmjs.com/package/graphene-pk11). Additional samples cover common **C** / **LunaJSP** actions (AES-GCM/CTR, CMAC, HMAC, digest, ECDH, DES3, destroy, mechanism list).

## Requirements

- Node.js 18+
- Luna Client installed and configured
- `npm install` in this directory

## Environment

```powershell
$env:ChrystokiConfigurationPath = "C:\Program Files\SafeNet\LunaClient"
$env:P11_LIB = "C:\Program Files\SafeNet\LunaClient\cryptoki.dll"
$env:LUNA_PIN = "<crypto-officer-pin>"
# Optional for encrypt/sign demos:
$env:SAMPLE_PLAINTEXT = "hello luna"
```

## Examples

```powershell
node enumerate_slots.js
node login_logout.js myPartition
node generate_aes_key.js myPartition myAesKey 256
node sign_using_rsa_sha256.js myPartition
node encrypt_using_aes-gcm.js myPartition
node pqc_mechanism_probe.js myPartition
```

## Coverage notes

| Area | Status |
|------|--------|
| Python PKCS#11 set | Full 1:1 Node ports |
| Common C/JSP crypto (AES modes, RSA/ECDSA sign, wrap) | Covered (see scripts in this folder) |
| **PQC** (ML-DSA / ML-KEM / HSS) | **Not implemented** — needs firmware 7.8.9+/7.9.0+ and PKCS#11 3.2 bindings. Use `pqc_mechanism_probe.js` to check the slot; use C/JSP PQC samples when firmware supports it |
| Java LunaKeyStore / LunaProvider-only | N/A in Node (use PKCS#11 object find/login instead) |
| SafeNet vendor extensions (SIM, Remote PED, CA_*) | Not ported (outside standard Cryptoki via graphene) |
| Luna Functionality Modules (FM) | Not ported |

These samples are for learning and testing only — not production use.

PIN prompts mask input when run on a TTY (or set `LUNA_PIN` to skip the prompt).
