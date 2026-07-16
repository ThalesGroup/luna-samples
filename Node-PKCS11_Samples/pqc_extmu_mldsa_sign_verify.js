#!/usr/bin/env node
/*********************************************************************************
 *                                                                                *
 * Ported from C_Samples/pqc/CKM_EXTMU_ML_DSA_Sign_Verify_demo.                   *
 * MIT license — https://mit-license.org/                                         *
 *                                                                                *
 *********************************************************************************
 * OBJECTIVE: Sign/verify with CKM_EXTMU_ML_DSA using a 64-byte external mu.
 */

"use strict";
const {
  usageAndExit,
  withPqcSession,
  generateMlDsaKeyPair,
  destroyPair,
  packSignAdditionalContext,
  ckR,
  CKM_EXTMU_ML_DSA,
  CKH_DETERMINISTIC_REQUIRED,
  CKP_ML_DSA_65,
} = require("./lib/pqc_helper");

console.log("\npqc_extmu_mldsa_sign_verify.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage: node pqc_extmu_mldsa_sign_verify.js <slot_label>",
    "Env: LUNA_PIN, P11_LIB\n",
  ]);
}

const slotLabel = process.argv[2];
// Dummy external mu (same pattern as C sample) — illustrates the signing flow only.
const externalMu = Buffer.from([
  0x08, 0x08, 0x08, 0x08, 0x0f, 0x09, 0x04, 0x02, 0x08, 0x0a, 0x0c, 0x09, 0x0f, 0x09, 0x0e, 0x07,
  0x0c, 0x05, 0x0d, 0x0b, 0x08, 0x06, 0x06, 0x06, 0x0d, 0x0c, 0x09, 0x02, 0x02, 0x0f, 0x09, 0x07,
  0x03, 0x0b, 0x01, 0x0b, 0x0f, 0x09, 0x05, 0x0f, 0x09, 0x05, 0x0d, 0x00, 0x0c, 0x05, 0x06, 0x0e,
  0x00, 0x07, 0x09, 0x0d, 0x0f, 0x07, 0x09, 0x0e, 0x08, 0x0f, 0x09, 0x0f, 0x00, 0x0e, 0x06, 0x09,
]);

withPqcSession(slotLabel, async ({ pkcs11, session }) => {
  const keys = generateMlDsaKeyPair(pkcs11, session, CKP_ML_DSA_65);
  console.log("ML-DSA-65 keypair generated.");

  const packed = packSignAdditionalContext(CKH_DETERMINISTIC_REQUIRED, null);
  const mech = { mechanism: CKM_EXTMU_ML_DSA, parameter: packed.buffer };

  pkcs11.C_SignInit(session, mech, keys.privateKey);
  const sig = pkcs11.C_Sign(session, externalMu, Buffer.alloc(8192));
  console.log("Signed external mu. signature length:", sig.length);

  pkcs11.C_VerifyInit(session, mech, keys.publicKey);
  pkcs11.C_Verify(session, externalMu, sig);
  console.log("Signature verified.\n");

  destroyPair(pkcs11, session, keys);
}).catch((e) => {
  console.error("FAILED:", ckR(e));
  process.exit(1);
});
