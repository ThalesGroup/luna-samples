#!/usr/bin/env node
/*********************************************************************************
 *                                                                                *
 * Ported from C_Samples/pqc Wrap/Unwrap_PQC_PrivateKey (combined self-test).     *
 * MIT license — https://mit-license.org/                                         *
 *                                                                                *
 *********************************************************************************
 * OBJECTIVE: Wrap an extractable ML-DSA private key with AES-KWP, then unwrap.
 * Requires partition policy allowing private-key wrap (often policy 1 / non-FIPS).
 * Session objects only — no files written.
 */

"use strict";
const {
  usageAndExit,
  withPqcSession,
  destroyPair,
  ckR,
  CKM_ML_DSA_KEY_PAIR_GEN,
  CKM_AES_KWP,
  CKK_ML_DSA,
  CKA_PARAMETER_SET,
  CKP_ML_DSA_65,
  pkcs11js,
} = require("./lib/pqc_helper");

console.log("\npqc_wrap_unwrap_private_key.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage: node pqc_wrap_unwrap_private_key.js <slot_label>",
    "Env: LUNA_PIN, P11_LIB\n",
  ]);
}

const slotLabel = process.argv[2];
const iv = Buffer.from([0x01, 0x02, 0x03, 0x04]);

withPqcSession(slotLabel, async ({ pkcs11, session }) => {
  // Extractable ML-DSA private key (session)
  const keys = pkcs11.C_GenerateKeyPair(
    session,
    { mechanism: CKM_ML_DSA_KEY_PAIR_GEN },
    [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
      { type: pkcs11js.CKA_TOKEN, value: false },
      { type: pkcs11js.CKA_VERIFY, value: true },
      { type: pkcs11js.CKA_KEY_TYPE, value: CKK_ML_DSA },
      { type: CKA_PARAMETER_SET, value: CKP_ML_DSA_65 },
    ],
    [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
      { type: pkcs11js.CKA_TOKEN, value: false },
      { type: pkcs11js.CKA_PRIVATE, value: true },
      { type: pkcs11js.CKA_SENSITIVE, value: true },
      { type: pkcs11js.CKA_EXTRACTABLE, value: true },
      { type: pkcs11js.CKA_SIGN, value: true },
      { type: pkcs11js.CKA_KEY_TYPE, value: CKK_ML_DSA },
    ]
  );
  console.log("Extractable ML-DSA-65 private key generated.");

  const wrapKey = pkcs11.C_GenerateKey(
    session,
    { mechanism: pkcs11js.CKM_AES_KEY_GEN },
    [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_SECRET_KEY },
      { type: pkcs11js.CKA_TOKEN, value: false },
      { type: pkcs11js.CKA_PRIVATE, value: true },
      { type: pkcs11js.CKA_SENSITIVE, value: true },
      { type: pkcs11js.CKA_ENCRYPT, value: true },
      { type: pkcs11js.CKA_DECRYPT, value: true },
      { type: pkcs11js.CKA_WRAP, value: true },
      { type: pkcs11js.CKA_UNWRAP, value: true },
      { type: pkcs11js.CKA_VALUE_LEN, value: 32 },
      { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_AES },
    ]
  );
  console.log("AES-256 wrapping key generated.");

  const wrapMech = { mechanism: CKM_AES_KWP, parameter: iv };
  let wrapped;
  try {
    wrapped = pkcs11.C_WrapKey(
      session,
      wrapMech,
      wrapKey,
      keys.privateKey,
      Buffer.alloc(16384)
    );
  } catch (e) {
    console.error(
      "C_WrapKey failed — partition may disallow private-key wrap:",
      ckR(e)
    );
    try {
      pkcs11.C_DestroyObject(session, wrapKey);
    } catch (_) {}
    destroyPair(pkcs11, session, keys);
    process.exitCode = 2;
    return;
  }
  console.log("Private key wrapped. wrapped length:", wrapped.length);

  const unwrapped = pkcs11.C_UnwrapKey(
    session,
    wrapMech,
    wrapKey,
    wrapped,
    [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
      { type: pkcs11js.CKA_TOKEN, value: false },
      { type: pkcs11js.CKA_PRIVATE, value: true },
      { type: pkcs11js.CKA_SENSITIVE, value: true },
      { type: pkcs11js.CKA_EXTRACTABLE, value: true },
      { type: pkcs11js.CKA_SIGN, value: true },
      { type: pkcs11js.CKA_KEY_TYPE, value: CKK_ML_DSA },
    ]
  );
  console.log("Private key unwrapped. handle:", unwrapped);

  // Smoke: sign with unwrapped key
  const plain = Buffer.from("wrap-unwrap smoke");
  const { packSignAdditionalContext, CKM_ML_DSA, CKH_HEDGE_PREFERRED } = require(
    "./lib/pqc_helper"
  );
  const ctx = Buffer.from("123456781234567812345678123456781234");
  const packed = packSignAdditionalContext(CKH_HEDGE_PREFERRED, ctx);
  const mech = { mechanism: CKM_ML_DSA, parameter: packed.buffer };
  pkcs11.C_SignInit(session, mech, unwrapped);
  const sig = pkcs11.C_Sign(session, plain, Buffer.alloc(8192));
  pkcs11.C_VerifyInit(session, mech, keys.publicKey);
  pkcs11.C_Verify(session, plain, sig);
  console.log("Sign/verify with unwrapped key OK.\n");

  try {
    pkcs11.C_DestroyObject(session, unwrapped);
  } catch (_) {}
  try {
    pkcs11.C_DestroyObject(session, wrapKey);
  } catch (_) {}
  destroyPair(pkcs11, session, keys);
}).catch((e) => {
  console.error("FAILED:", ckR(e));
  process.exit(1);
});
