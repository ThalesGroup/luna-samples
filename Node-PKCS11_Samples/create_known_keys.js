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
 * - Import a known AES key value into Luna by encrypting plaintext key bytes
 *   with an ephemeral KEK (CKM_AES_KW) then unwrapping (mirrors C CreateKnownKeys).
 */

"use strict";
const {
  graphene,
  withSession,
  usageAndExit,
  toHex,
  CKM_AES_KW,
} = require("./lib/helper");

console.log("\ncreate_known_keys.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node create_known_keys.js <slot_label>",
    "",
    "Example:",
    "node create_known_keys.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];

/** Demo known AES-128 key material (same bytes as the C sample). */
const KNOWN_KEY = Buffer.from([
  0x10, 0xaa, 0x32, 0x56, 0xa1, 0x87, 0xf1, 0x63, 0x82, 0xd3, 0x4d, 0x95, 0xac,
  0x76, 0x01, 0x63,
]);

(async () => {
  await withSession(slotLabel, async (session) => {
    const wrappingKey = session.generateKey(graphene.KeyGenMechanism.AES, {
      keyType: graphene.KeyType.AES,
      valueLen: 16,
      token: false,
      encrypt: true,
      unwrap: true,
    });
    console.log("Ephemeral AES KEK generated.");
    const iv = session.generateRandom(8);
    console.log("IV generated for CKM_AES_KW.");
    const alg = { name: CKM_AES_KW, params: iv };
    const cipher = session.createCipher(alg, wrappingKey);
    const encrypted = cipher.once(KNOWN_KEY, Buffer.alloc(KNOWN_KEY.length + 32));
    console.log("Known key bytes encrypted.");
    const imported = session.unwrapKey(alg, wrappingKey, encrypted, {
      class: graphene.ObjectClass.SECRET_KEY,
      keyType: graphene.KeyType.AES,
      token: false,
      private: true,
      sensitive: true,
      extractable: false,
      encrypt: true,
      decrypt: true,
      valueLen: 16,
    });
    console.log("Known key unwrapped into HSM.");
    console.log("  --> encrypted bytes :", toHex(encrypted));
    console.log("  --> handle          :", imported.handle.toString("hex"));
    console.log();
  });
})();
