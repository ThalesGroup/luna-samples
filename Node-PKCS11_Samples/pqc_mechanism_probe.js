#!/usr/bin/env node
/*********************************************************************************
 *                                                                                *
 * Ported from ThalesGroup/luna-samples. The original project is provided under   *
 * the MIT license (https://mit-license.org/).                                    *
 *                                                                                *
 * Copyright © 2025 Thales Group (original samples)                               *
 *                                                                                *
 *********************************************************************************

 * OBJECTIVE:
 * - Probe whether this slot advertises PQC mechanisms (ML-DSA / ML-KEM / HSS).
 * - C/JSP PQC samples need firmware 7.8.9+ (HSS) or 7.9.0+ (ML-DSA/ML-KEM) and
 *   Luna Client 10.9+. Older firmware reports these mechanisms as absent.
 * - Full PQC keygen/sign samples are not shipped here until graphene-pk11 / pkcs11js
 *   expose the PKCS#11 3.2 PQC templates; this probe only lists advertised mechs.
 */

"use strict";
const {
  graphene,
  requireP11Lib,
  findSlotByLabel,
  usageAndExit,
} = require("./lib/helper");
const { mechanismName } = require("./lib/mechanism_names");

console.log("\npqc_mechanism_probe.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node pqc_mechanism_probe.js <slot_label>",
    "",
    "Example:",
    "node pqc_mechanism_probe.js myPartition\n",
  ]);
}

const slotLabel = process.argv[2];
const PQC_HINTS = [/ML_DSA/i, /ML_KEM/i, /HSS/i, /KYBER/i, /DILITHIUM/i, /SPHINCS/i];
/** Known PKCS#11 / Luna PQC mechanism type IDs (graphene often labels these "unknown"). */
const PQC_TYPES = new Set([
  0x0f, // CKM_ML_KEM_KEY_PAIR_GEN
  0x17, // CKM_ML_KEM
  0x1c, // CKM_ML_DSA_KEY_PAIR_GEN
  0x1d, // CKM_ML_DSA
  0x1f, // CKM_HASH_ML_DSA
  0x23, 0x24, 0x25, 0x26, // HASH_ML_DSA_SHA*
  0x27, 0x28, 0x29, 0x2a, // HASH_ML_DSA_SHA3_*
  0x2b, 0x2c, // HASH_ML_DSA_SHAKE*
  0x4032, // CKM_HSS_KEY_PAIR_GEN
  0x4033, // CKM_HSS
  0x80000175, // CKM_EXTMU_ML_DSA
]);

(async () => {
  const pkcs11Library = requireP11Lib();
  const mod = graphene.Module.load(pkcs11Library, "Luna");
  mod.initialize();
  try {
    const slot = findSlotByLabel(mod, slotLabel);
    if (!slot) {
      console.log("Incorrect token label.\n");
      process.exitCode = 1;
      return;
    }
    const token = slot.getToken();
    console.log("Token label  :", String(token.label).trim());
    console.log("Token model  :", String(token.model).trim());
    console.log(
      "Firmware     :",
      token.firmwareVersion.major + "." + token.firmwareVersion.minor
    );
    const mechs = slot.getMechanisms();
    const found = [];
    for (let i = 0; i < mechs.length; i++) {
      const m = mechs.items(i);
      const id = Number(m.type) >>> 0;
      const name = mechanismName(id, m.name);
      if (PQC_TYPES.has(id) || PQC_HINTS.some((re) => re.test(name))) {
        found.push({ name, id });
      }
    }
    if (found.length) {
      console.log("\nPQC-related mechanisms found (" + found.length + "):");
      for (const x of found) {
        console.log("  -", x.name.padEnd(32), "0x" + x.id.toString(16));
      }
      console.log("\nFirmware advertises PQC. Node samples (raw pkcs11js):");
      console.log("  node pqc_mldsa_generate_keypair.js <slot_label> [44|65|87]");
      console.log("  node pqc_mldsa_sign_verify.js <slot_label>");
      console.log("  node pqc_mlkem_encapsulate_decapsulate.js <slot_label> [512|768|1024]");
      console.log("See README.md PQC section for the full list.\n");
    } else {
      console.log("\nNo PQC mechanisms advertised on this slot.");
      console.log("C/JSP requirements (for reference):");
      console.log("  - HSS     : firmware 7.8.9+, client 10.8+");
      console.log("  - ML-DSA / ML-KEM : firmware 7.9.0+, client 10.9+\n");
    }
    process.exitCode = 0;
  } finally {
    try {
      mod.finalize();
    } catch (_) {
      /* ignore */
    }
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
