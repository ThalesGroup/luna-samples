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
 * - It also shows how to set user specified PKCS#11 attributes on the key.
 */

"use strict";
const { graphene, withSession, usageAndExit } = require("./lib/helper");

console.log("\ngenerate_aes_key2.js\n");

if (process.argv.length !== 5) {
  usageAndExit([
    "Usage:",
    "node generate_aes_key2.js <slot_label> <secret_key_label> <keysize (128/192/256)>",
    "",
    "Example:",
    "node generate_aes_key2.js myPartition myAesKey 128\n",
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
      id: Buffer.from("1123581321345589", "utf8"),
      token: true,
      private: true,
      extractable: true,
      modifiable: true,
      sensitive: true,
      wrap: true,
      unwrap: true,
      encrypt: true,
      decrypt: true,
      sign: true,
      verify: true,
    });
    console.log("AES key generated with label : ", secretKeyLabel);
    console.log();
  });
})();

