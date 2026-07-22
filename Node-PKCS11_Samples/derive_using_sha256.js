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
 * - Derive an AES key from a GENERIC_SECRET base key using CKM_SHA256_KEY_DERIVATION.
 * - Mirrors C CKM_SHA256_KEY_DERIVATION_demo (not FIPS-approved on some configs).
 */

"use strict";
const { graphene, withSession, usageAndExit } = require("./lib/helper");

console.log("\nderive_using_sha256.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node derive_using_sha256.js <slot_label>",
    "",
    "Example:",
    "node derive_using_sha256.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];
(async () => {
  await withSession(slotLabel, async (session) => {
    const base = session.generateKey(graphene.KeyGenMechanism.GENERIC_SECRET, {
      keyType: graphene.KeyType.GENERIC_SECRET,
      valueLen: 32,
      token: false,
      derive: true,
      sensitive: true,
    });
    console.log("Base GENERIC_SECRET key generated.");
    const derived = session.deriveKey(
      graphene.MechanismEnum.SHA256_KEY_DERIVATION,
      base,
      {
        class: graphene.ObjectClass.SECRET_KEY,
        keyType: graphene.KeyType.AES,
        valueLen: 32,
        token: false,
        encrypt: true,
        decrypt: true,
      }
    );
    console.log("AES-256 key derived via SHA256_KEY_DERIVATION.");
    console.log("  --> handle :", derived.handle.toString("hex"));
    console.log();
  });
})();
