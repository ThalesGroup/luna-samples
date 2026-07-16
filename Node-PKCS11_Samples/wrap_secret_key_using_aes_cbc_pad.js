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
 * - Wrap/unwrap a secret key with AES_CBC_PAD (mirrors JSP WrapUnwrapSecretKeyUsing_AES_CBC_PAD).
 */

"use strict";
const { graphene, withSession, usageAndExit, toHex } = require("./lib/helper");

console.log("\nwrap_secret_key_using_aes_cbc_pad.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node wrap_secret_key_using_aes_cbc_pad.js <slot_label>",
    "",
    "Example:",
    "node wrap_secret_key_using_aes_cbc_pad.js myPartition\n",
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
    const iv = Buffer.alloc(16, 0x11);
    const alg = {
      name: graphene.MechanismEnum.AES_CBC_PAD,
      params: new graphene.AesCbcParams(iv),
    };
    const wrapped = session.wrapKey(alg, wrappingKey, keyToWrap);
    console.log("Key wrapped with AES_CBC_PAD.");
    const unwrapped = session.unwrapKey(alg, wrappingKey, wrapped, {
      class: graphene.ObjectClass.SECRET_KEY,
      keyType: graphene.KeyType.AES,
      token: false,
      encrypt: true,
      decrypt: true,
      extractable: true,
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
