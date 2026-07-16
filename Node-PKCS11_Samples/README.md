# Node-PKCS11 Samples for Luna HSMs

Node.js ports of the `Python-PKCS11_Samples` from [ThalesGroup/luna-samples](https://github.com/ThalesGroup/luna-samples), using [`graphene-pk11`](https://www.npmjs.com/package/graphene-pk11).

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
```

These samples are for learning and testing only — not production use.
