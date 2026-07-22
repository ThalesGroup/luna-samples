#!/usr/bin/env node
/*********************************************************************************
 *                                                                                *
 * Ported from C_Samples/pqc/CKM_HSS_KEY_PAIR_GEN_demo (defaults for demo).       *
 * MIT license — https://mit-license.org/                                         *
 *                                                                                *
 *********************************************************************************
 * OBJECTIVE: Generate an ephemeral HSS keypair (CKM_HSS_KEY_PAIR_GEN).
 * Default: level=1, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8 (fast enough for demos).
 * Requires firmware 7.8.9+.
 */

"use strict";
const {
  usageAndExit,
  withPqcSession,
  destroyPair,
  ckR,
  ulong,
  CKM_HSS_KEY_PAIR_GEN,
  CKK_HSS,
  CKA_HSS_LEVELS,
  CKA_HSS_LMS_TYPES,
  CKA_HSS_LMOTS_TYPES,
  LMS_SHA256_M32_H5,
  LMOTS_SHA256_N32_W8,
  pkcs11js,
} = require("./lib/pqc_helper");

console.log("\npqc_hss_generate_keypair.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage: node pqc_hss_generate_keypair.js <slot_label>",
    "Env: LUNA_PIN, P11_LIB\n",
  ]);
}

const slotLabel = process.argv[2];
const hssLevel = 1;
const lmsTypes = ulong(LMS_SHA256_M32_H5);
const lmotsTypes = ulong(LMOTS_SHA256_N32_W8);

withPqcSession(slotLabel, async ({ pkcs11, session }) => {
  console.log(
    "Generating HSS keypair (level=" +
      hssLevel +
      ", LMS_M32_H5, LMOTS_N32_W8, session)..."
  );
  console.log("(HSS keygen can take a while.)");
  const keys = pkcs11.C_GenerateKeyPair(
    session,
    { mechanism: CKM_HSS_KEY_PAIR_GEN },
    [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
      { type: pkcs11js.CKA_TOKEN, value: false },
      { type: pkcs11js.CKA_PRIVATE, value: false },
      { type: pkcs11js.CKA_VERIFY, value: true },
      { type: pkcs11js.CKA_KEY_TYPE, value: CKK_HSS },
      { type: pkcs11js.CKA_LABEL, value: "node-hss-pub" },
    ],
    [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
      { type: pkcs11js.CKA_TOKEN, value: false },
      { type: pkcs11js.CKA_PRIVATE, value: true },
      { type: pkcs11js.CKA_SENSITIVE, value: true },
      { type: pkcs11js.CKA_EXTRACTABLE, value: false },
      { type: pkcs11js.CKA_SIGN, value: true },
      { type: pkcs11js.CKA_KEY_TYPE, value: CKK_HSS },
      { type: CKA_HSS_LEVELS, value: hssLevel },
      { type: CKA_HSS_LMS_TYPES, value: lmsTypes },
      { type: CKA_HSS_LMOTS_TYPES, value: lmotsTypes },
      { type: pkcs11js.CKA_LABEL, value: "node-hss-priv" },
    ]
  );
  console.log("SUCCESS");
  console.log("  public  :", keys.publicKey);
  console.log("  private :", keys.privateKey);
  destroyPair(pkcs11, session, keys);
  console.log("Destroyed session keypair.\n");
}).catch((e) => {
  console.error("FAILED:", ckR(e));
  process.exit(1);
});
