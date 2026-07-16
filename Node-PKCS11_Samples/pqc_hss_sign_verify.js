#!/usr/bin/env node
/*********************************************************************************
 *                                                                                *
 * Ported from C_Samples/pqc HSS sign + verify (combined, session keys).          *
 * MIT license — https://mit-license.org/                                         *
 *                                                                                *
 *********************************************************************************
 * OBJECTIVE: Generate ephemeral HSS keypair, sign data with CKM_HSS, verify.
 */

"use strict";
const {
  usageAndExit,
  withPqcSession,
  destroyPair,
  ckR,
  ulong,
  CKM_HSS_KEY_PAIR_GEN,
  CKM_HSS,
  CKK_HSS,
  CKA_HSS_LEVELS,
  CKA_HSS_LMS_TYPES,
  CKA_HSS_LMOTS_TYPES,
  CKA_HSS_KEYS_REMAINING,
  LMS_SHA256_M32_H5,
  LMOTS_SHA256_N32_W8,
  pkcs11js,
} = require("./lib/pqc_helper");

console.log("\npqc_hss_sign_verify.js\n");

if (process.argv.length !== 3) {
  usageAndExit(["Usage: node pqc_hss_sign_verify.js <slot_label>", "Env: LUNA_PIN, P11_LIB\n"]);
}

const slotLabel = process.argv[2];
const data = Buffer.from("HSS Node sample plaintext for sign/verify.");
const hssLevel = 1;

withPqcSession(slotLabel, async ({ pkcs11, session }) => {
  console.log("Generating HSS keypair (session, level=1)...");
  const keys = pkcs11.C_GenerateKeyPair(
    session,
    { mechanism: CKM_HSS_KEY_PAIR_GEN },
    [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
      { type: pkcs11js.CKA_TOKEN, value: false },
      { type: pkcs11js.CKA_VERIFY, value: true },
      { type: pkcs11js.CKA_KEY_TYPE, value: CKK_HSS },
    ],
    [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
      { type: pkcs11js.CKA_TOKEN, value: false },
      { type: pkcs11js.CKA_PRIVATE, value: true },
      { type: pkcs11js.CKA_SENSITIVE, value: true },
      { type: pkcs11js.CKA_SIGN, value: true },
      { type: pkcs11js.CKA_KEY_TYPE, value: CKK_HSS },
      { type: CKA_HSS_LEVELS, value: hssLevel },
      { type: CKA_HSS_LMS_TYPES, value: ulong(LMS_SHA256_M32_H5) },
      { type: CKA_HSS_LMOTS_TYPES, value: ulong(LMOTS_SHA256_N32_W8) },
    ]
  );
  console.log("Keypair generated.");

  try {
    const rem = pkcs11.C_GetAttributeValue(session, keys.privateKey, [
      { type: CKA_HSS_KEYS_REMAINING },
    ]);
    let v = rem[0].value;
    if (Buffer.isBuffer(v) && v.length >= 4) v = v.readUInt32LE(0);
    console.log("HSS keys remaining:", v);
  } catch (_) {}

  pkcs11.C_SignInit(session, { mechanism: CKM_HSS }, keys.privateKey);
  const sig = pkcs11.C_Sign(session, data, Buffer.alloc(65536));
  console.log("Signed. signature length:", sig.length);

  pkcs11.C_VerifyInit(session, { mechanism: CKM_HSS }, keys.publicKey);
  pkcs11.C_Verify(session, data, sig);
  console.log("Signature verified.\n");

  destroyPair(pkcs11, session, keys);
}).catch((e) => {
  console.error("FAILED:", ckR(e));
  process.exit(1);
});
