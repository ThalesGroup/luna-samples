#!/usr/bin/env node
/*********************************************************************************
 *                                                                                *
 * Ported from ThalesGroup/luna-samples C_Samples/pqc (ML-DSA keygen).            *
 * MIT license — https://mit-license.org/                                         *
 *                                                                                *
 *********************************************************************************
 * OBJECTIVE: Generate an ephemeral ML-DSA keypair (CKM_ML_DSA_KEY_PAIR_GEN).
 * Requires firmware 7.9+ / client 10.9+. Uses raw pkcs11js (PQC not in graphene).
 */

"use strict";
const {
  usageAndExit,
  withPqcSession,
  generateMlDsaKeyPair,
  destroyPair,
  ckR,
  CKA_PARAMETER_SET,
  CKK_ML_DSA,
  ML_DSA_SETS,
  pkcs11js,
} = require("./lib/pqc_helper");

console.log("\npqc_mldsa_generate_keypair.js\n");

if (process.argv.length < 3 || process.argv.length > 4) {
  usageAndExit([
    "Usage: node pqc_mldsa_generate_keypair.js <slot_label> [44|65|87]",
    "Env: LUNA_PIN, P11_LIB\n",
  ]);
}

const slotLabel = process.argv[2];
const paramArg = process.argv[3] || "65";
const paramSet = ML_DSA_SETS[paramArg];
if (paramSet == null) {
  console.error("Invalid parameter set. Use 44, 65, or 87.");
  process.exit(1);
}

withPqcSession(slotLabel, async ({ pkcs11, session }) => {
  console.log("Generating ML-DSA-" + paramArg + " keypair (session objects)...");
  const keys = generateMlDsaKeyPair(pkcs11, session, paramSet);
  console.log("SUCCESS");
  console.log("  public  :", keys.publicKey);
  console.log("  private :", keys.privateKey);
  try {
    const attrs = pkcs11.C_GetAttributeValue(session, keys.publicKey, [
      { type: CKA_PARAMETER_SET },
      { type: pkcs11js.CKA_KEY_TYPE },
    ]);
    for (const a of attrs) {
      let v = a.value;
      if (Buffer.isBuffer(v) && v.length >= 4) v = v.readUInt32LE(0);
      console.log(
        "  " + (a.type === CKA_PARAMETER_SET ? "CKA_PARAMETER_SET" : "CKA_KEY_TYPE") + ":",
        v,
        a.type === pkcs11js.CKA_KEY_TYPE && v === CKK_ML_DSA ? "(CKK_ML_DSA)" : ""
      );
    }
  } catch (e) {
    console.log("  (readback skipped:", ckR(e) + ")");
  }
  destroyPair(pkcs11, session, keys);
  console.log("Destroyed session keypair.\n");
}).catch((e) => {
  console.error("FAILED:", ckR(e));
  process.exit(1);
});
