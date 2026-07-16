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
 * - This sample code demonstrates how to generate an AES key.
 * - It allows you to set your own key label and choose a key size.
 */

"use strict";
const { graphene, withSession, usageAndExit } = require("./lib/helper");

console.log("\ngenerate_aes_key.js\n");

if (process.argv.length !== 5) {
  usageAndExit([
    "Usage:",
    "node generate_aes_key.js <slot_label> <secret_key_label> <keysize (128/192/256)>",
    "",
    "Example:",
    "node generate_aes_key.js myPartition myAesKey 128\n",
  ]);
}

const slotLabel = process.argv[2];
const secretKeyLabel = process.argv[3];
const keySize = parseInt(process.argv[4], 10);
if (![128, 192, 256].includes(keySize)) {
  console.log("AES key size invalid.\n");
  process.exit(1);
}

(async () => {
  await withSession(slotLabel, async (session) => {
    session.generateKey(graphene.KeyGenMechanism.AES, {
      keyType: graphene.KeyType.AES,
      valueLen: keySize / 8,
      label: secretKeyLabel,
      token: true,
      private: true,
      sensitive: true,
      encrypt: true,
      decrypt: true,
      wrap: true,
      unwrap: true,
      extractable: true,
    });
    console.log("AES key generated with label : ", secretKeyLabel);
    console.log();
  });
})();

