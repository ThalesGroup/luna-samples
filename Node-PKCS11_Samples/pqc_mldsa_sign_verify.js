#!/usr/bin/env node
/*********************************************************************************
 *                                                                                *
 * Ported from ThalesGroup/luna-samples C_Samples/pqc/CKM_ML_DSA_Sign_Verify.     *
 * MIT license — https://mit-license.org/                                         *
 *                                                                                *
 *********************************************************************************
 * OBJECTIVE: Pure ML-DSA sign/verify (CKM_ML_DSA) with CK_SIGN_ADDITIONAL_CONTEXT.
 */

"use strict";
const {
  usageAndExit,
  withPqcSession,
  generateMlDsaKeyPair,
  destroyPair,
  packSignAdditionalContext,
  ckR,
  CKM_ML_DSA,
  CKH_HEDGE_PREFERRED,
  CKP_ML_DSA_65,
} = require("./lib/pqc_helper");

console.log("\npqc_mldsa_sign_verify.js\n");

if (process.argv.length !== 3) {
  usageAndExit(["Usage: node pqc_mldsa_sign_verify.js <slot_label>", "Env: LUNA_PIN, P11_LIB\n"]);
}

const slotLabel = process.argv[2];
const plainText = Buffer.from(
  "Hello World, I've been waiting for the chance to see your face."
);
// Must outlive SignInit/VerifyInit (C sample stack-local context was a bug).
const context = Buffer.from("123456781234567812345678123456781234");

withPqcSession(slotLabel, async ({ pkcs11, session }) => {
  const keys = generateMlDsaKeyPair(pkcs11, session, CKP_ML_DSA_65);
  console.log("ML-DSA-65 keypair generated.");

  const packed = packSignAdditionalContext(CKH_HEDGE_PREFERRED, context);
  const mech = { mechanism: CKM_ML_DSA, parameter: packed.buffer };

  pkcs11.C_SignInit(session, mech, keys.privateKey);
  let sig = pkcs11.C_Sign(session, plainText, Buffer.alloc(8192));
  console.log("Signed. signature length:", sig.length);

  pkcs11.C_VerifyInit(session, mech, keys.publicKey);
  pkcs11.C_Verify(session, plainText, sig);
  console.log("Signature verified.\n");

  destroyPair(pkcs11, session, keys);
}).catch((e) => {
  console.error("FAILED:", ckR(e));
  process.exit(1);
});
