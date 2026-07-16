#!/usr/bin/env node
/*********************************************************************************
 *                                                                                *
 * Ported from ThalesGroup/luna-samples C_Samples/pqc (ML-KEM keygen).            *
 * MIT license — https://mit-license.org/                                         *
 *                                                                                *
 *********************************************************************************
 * OBJECTIVE: Generate an ephemeral ML-KEM keypair (CKM_ML_KEM_KEY_PAIR_GEN).
 */

"use strict";
const {
  usageAndExit,
  withPqcSession,
  generateMlKemKeyPair,
  destroyPair,
  ckR,
  CKA_PARAMETER_SET,
  ML_KEM_SETS,
  pkcs11js,
} = require("./lib/pqc_helper");

console.log("\npqc_mlkem_generate_keypair.js\n");

if (process.argv.length < 3 || process.argv.length > 4) {
  usageAndExit([
    "Usage: node pqc_mlkem_generate_keypair.js <slot_label> [512|768|1024]",
    "Env: LUNA_PIN, P11_LIB\n",
  ]);
}

const slotLabel = process.argv[2];
const paramArg = process.argv[3] || "768";
const paramSet = ML_KEM_SETS[paramArg];
if (paramSet == null) {
  console.error("Invalid parameter set. Use 512, 768, or 1024.");
  process.exit(1);
}

withPqcSession(slotLabel, async ({ pkcs11, session }) => {
  console.log("Generating ML-KEM-" + paramArg + " keypair (session objects)...");
  const keys = generateMlKemKeyPair(pkcs11, session, paramSet);
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
      console.log("  attr 0x" + a.type.toString(16) + ":", v);
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
