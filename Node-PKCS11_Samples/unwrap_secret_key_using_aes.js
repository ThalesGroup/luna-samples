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
 * - Unwrap an AES-wrapped secret key from a file.
 * - Supports NIST AES_KEY_WRAP blobs and Luna CKM_AES_KW blobs written by
 *   wrap_secret_key_using_aes.js (KW1 header + 8-byte IV + ciphertext).
 */

"use strict";
const fs = require("fs");
const {
  graphene,
  withSession,
  usageAndExit,
  findKeyByLabel,
  CKM_AES_KW,
} = require("./lib/helper");

console.log("\nunwrap_secret_key_using_aes.js\n");

if (process.argv.length !== 6) {
  usageAndExit([
    "Usage:",
    "node unwrap_secret_key_using_aes.js <slot_label> <wrapping_key_label> <unwrapped_key_label> <wrapped_key_file>",
    "",
    "Example:",
    "node unwrap_secret_key_using_aes.js myPartition KEK myEncryptionKey2 myEncryptionKey.dat\n",
  ]);
}

const [slotLabel, wrappingKeyLabel, unwrappedKeyLabel, wrappedKeyFile] =
  process.argv.slice(2);

(async () => {
  await withSession(slotLabel, async (session) => {
    const wrappingKey = findKeyByLabel(
      session,
      wrappingKeyLabel,
      graphene.ObjectClass.SECRET_KEY
    );
    console.log("\t> Wrapping key found : ", wrappingKeyLabel);

    const file = fs.readFileSync(wrappedKeyFile);
    let alg;
    let wrapped;
    let valueLen;
    if (file.length >= 12 && file.slice(0, 4).equals(Buffer.from("KW1\0"))) {
      const iv = file.slice(4, 12);
      wrapped = file.slice(12);
      alg = { name: CKM_AES_KW, params: iv };
      console.log("\t> Format           : Luna CKM_AES_KW");
    } else {
      wrapped = file;
      alg = graphene.MechanismEnum.AES_KEY_WRAP;
      console.log("\t> Format           : AES_KEY_WRAP");
    }
    // AES key-wrap ciphertext is key length + 8 bytes
    valueLen = wrapped.length - 8;

    const unwrapped = session.unwrapKey(alg, wrappingKey, wrapped, {
      class: graphene.ObjectClass.SECRET_KEY,
      keyType: graphene.KeyType.AES,
      label: unwrappedKeyLabel,
      token: true,
      private: true,
      sensitive: true,
      encrypt: true,
      decrypt: true,
      extractable: true,
      valueLen,
    });
    console.log("Key unwrapped successfully:", unwrapped.label, "\n");
  });
})();
