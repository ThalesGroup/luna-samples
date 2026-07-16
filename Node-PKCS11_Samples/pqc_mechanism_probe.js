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
 *   Luna Client 10.9+. This lab appliance (often 7.7.x) will report them as absent.
 * - Full PQC keygen/sign samples are not shipped here until graphene-pk11 / pkcs11js
 *   expose the PKCS#11 3.2 PQC templates and a firmware that supports them is available.
 */

"use strict";
const { graphene, requireP11Lib, findSlotByLabel, usageAndExit } = require("./lib/helper");

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
const PQC_HINTS = [/ML_DSA/i, /ML_KEM/i, /HSS/i, /KYBER/i, /DILITHIUM/i];

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
    console.log("Token model   :", String(token.model).trim());
    console.log(
      "Firmware      :",
      token.firmwareVersion.major + "." + token.firmwareVersion.minor
    );
    const mechs = slot.getMechanisms();
    const found = [];
    for (let i = 0; i < mechs.length; i++) {
      const m = mechs.items(i);
      if (PQC_HINTS.some((re) => re.test(m.name))) found.push(m.name);
    }
    if (found.length) {
      console.log("\nPQC-related mechanisms found:");
      for (const n of found) console.log("  -", n);
      console.log(
        "\nFirmware appears PQC-capable. Full Node ML-DSA/ML-KEM demos are not in this branch yet"
      );
      console.log(
        "(need PKCS#11 3.2 param templates in the Node binding). Use C/JSP PQC samples for now.\n"
      );
    } else {
      console.log("\nNo PQC mechanisms advertised on this slot.");
      console.log("C/JSP requirements (for reference):");
      console.log("  - HSS     : firmware 7.8.9+, client 10.8+");
      console.log("  - ML-DSA / ML-KEM : firmware 7.9.0+, client 10.9+");
      console.log(
        "This partition cannot run those PQC samples until firmware is upgraded.\n"
      );
      process.exitCode = 2;
    }
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
