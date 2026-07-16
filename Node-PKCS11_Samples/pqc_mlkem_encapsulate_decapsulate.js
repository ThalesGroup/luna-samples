#!/usr/bin/env node
/*********************************************************************************
 *                                                                                *
 * Ported from C_Samples/pqc/CKM_ML_KEM_Encapsulate_Decapsulate_demo.             *
 * MIT license — https://mit-license.org/                                         *
 *                                                                                *
 *********************************************************************************
 * OBJECTIVE: Encapsulate/decapsulate an AES-256 key via Luna CA_EncapsulateKey /
 *            CA_DecapsulateKey (PKCS#11 3.2 C_EncapsulateKey alias on Luna).
 */

"use strict";
const {
  usageAndExit,
  withPqcSession,
  generateMlKemKeyPair,
  destroyPair,
  encapsulateAesKey,
  decapsulateAesKey,
  numberToHandle,
  ckR,
  ML_KEM_SETS,
  ML_KEM_CT_LEN,
} = require("./lib/pqc_helper");

console.log("\npqc_mlkem_encapsulate_decapsulate.js\n");

if (process.argv.length < 3 || process.argv.length > 4) {
  usageAndExit([
    "Usage: node pqc_mlkem_encapsulate_decapsulate.js <slot_label> [512|768|1024]",
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
const ctLen = ML_KEM_CT_LEN[paramSet];

withPqcSession(slotLabel, async ({ pkcs11, session, libPath }) => {
  const keys = generateMlKemKeyPair(pkcs11, session, paramSet);
  console.log("ML-KEM-" + paramArg + " keypair generated.");

  const enc = encapsulateAesKey(libPath, session, keys.publicKey, ctLen);
  console.log("AES-256 encapsulated. ciphertext length:", enc.ciphertext.length);
  console.log("  encapsulated key handle:", enc.keyHandle);

  const decHandle = decapsulateAesKey(
    libPath,
    session,
    keys.privateKey,
    enc.ciphertext
  );
  console.log("AES-256 decapsulated. key handle:", decHandle);

  try {
    pkcs11.C_DestroyObject(session, numberToHandle(enc.keyHandle));
  } catch (_) {}
  try {
    pkcs11.C_DestroyObject(session, numberToHandle(decHandle));
  } catch (_) {}
  destroyPair(pkcs11, session, keys);
  console.log("SUCCESS\n");
}).catch((e) => {
  console.error("FAILED:", ckR(e));
  process.exit(1);
});
