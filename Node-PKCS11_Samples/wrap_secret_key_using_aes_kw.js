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
 * - Wrap/unwrap a secret key with Luna CKM_AES_KW (mirrors C CKM_AES_KW_demo /
 *   JSP WrapUnwrapSecretKeyUsing_AES_KW).
 */

"use strict";
const {
  graphene,
  withSession,
  usageAndExit,
  toHex,
  CKM_AES_KW,
} = require("./lib/helper");

console.log("\nwrap_secret_key_using_aes_kw.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node wrap_secret_key_using_aes_kw.js <slot_label>",
    "",
    "Example:",
    "node wrap_secret_key_using_aes_kw.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];
(async () => {
  await withSession(slotLabel, async (session) => {
    const wrappingKey = session.generateKey(graphene.KeyGenMechanism.AES, {
      keyType: graphene.KeyType.AES,
      valueLen: 16,
      token: false,
      wrap: true,
      unwrap: true,
    });
    const keyToWrap = session.generateKey(graphene.KeyGenMechanism.AES, {
      keyType: graphene.KeyType.AES,
      valueLen: 16,
      token: false,
      extractable: true,
      encrypt: true,
      decrypt: true,
    });
    console.log("AES session keys generated.");
    const iv = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    const alg = { name: CKM_AES_KW, params: iv };
    const wrapped = session.wrapKey(alg, wrappingKey, keyToWrap);
    console.log("Key wrapped with CKM_AES_KW.");
    const unwrapped = session.unwrapKey(alg, wrappingKey, wrapped, {
      class: graphene.ObjectClass.SECRET_KEY,
      keyType: graphene.KeyType.AES,
      token: false,
      encrypt: true,
      decrypt: true,
      extractable: true,
      valueLen: 16,
    });
    console.log("Key unwrapped.");
    console.log(
      "  --> wrapped bytes :",
      wrapped.length,
      toHex(wrapped).slice(0, 32) + "..."
    );
    console.log("  --> handle        :", unwrapped.handle.toString("hex"));
    console.log();
  });
})();
