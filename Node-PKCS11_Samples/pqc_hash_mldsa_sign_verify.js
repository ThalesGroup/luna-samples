#!/usr/bin/env node
/*********************************************************************************
 *                                                                                *
 * Ported from ThalesGroup/luna-samples C_Samples/pqc/CKM_HASH_ML_DSA_Sign_Verify.*
 * MIT license — https://mit-license.org/                                         *
 *                                                                                *
 *********************************************************************************
 * OBJECTIVE: Sign/verify a pre-computed SHA-256 digest with CKM_HASH_ML_DSA.
 */

"use strict";
const {
  usageAndExit,
  withPqcSession,
  generateMlDsaKeyPair,
  destroyPair,
  packHashSignAdditionalContext,
  ckR,
  CKM_HASH_ML_DSA,
  CKM_SHA256,
  CKH_DETERMINISTIC_REQUIRED,
  CKP_ML_DSA_65,
} = require("./lib/pqc_helper");

console.log("\npqc_hash_mldsa_sign_verify.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage: node pqc_hash_mldsa_sign_verify.js <slot_label>",
    "Env: LUNA_PIN, P11_LIB\n",
  ]);
}

const slotLabel = process.argv[2];
const plainText = Buffer.from(
  "Hello World, I've been waiting for the chance to see your face."
);

withPqcSession(slotLabel, async ({ pkcs11, session }) => {
  const keys = generateMlDsaKeyPair(pkcs11, session, CKP_ML_DSA_65);
  console.log("ML-DSA-65 keypair generated.");

  pkcs11.C_DigestInit(session, { mechanism: CKM_SHA256 });
  const digest = pkcs11.C_Digest(session, plainText, Buffer.alloc(64));
  console.log("SHA-256 digest length:", digest.length);

  const packed = packHashSignAdditionalContext(
    CKH_DETERMINISTIC_REQUIRED,
    null,
    CKM_SHA256
  );
  const mech = { mechanism: CKM_HASH_ML_DSA, parameter: packed.buffer };

  pkcs11.C_SignInit(session, mech, keys.privateKey);
  const sig = pkcs11.C_Sign(session, digest, Buffer.alloc(8192));
  console.log("Signed pre-hash. signature length:", sig.length);

  pkcs11.C_VerifyInit(session, mech, keys.publicKey);
  pkcs11.C_Verify(session, digest, sig);
  console.log("Signature verified.\n");

  destroyPair(pkcs11, session, keys);
}).catch((e) => {
  console.error("FAILED:", ckR(e));
  process.exit(1);
});
