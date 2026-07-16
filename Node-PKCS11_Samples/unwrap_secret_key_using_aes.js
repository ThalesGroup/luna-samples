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
 * - This sample demonstrates how to unwrap an encrypted secret key from a file into the HSM.
 * - The wrapping key used for wrap is required to unwrap.
 */

"use strict";
const fs = require("fs");
const { graphene, withSession, usageAndExit, findKeyByLabel } = require("./lib/helper");

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

    const wrapped = fs.readFileSync(wrappedKeyFile);
    const unwrapped = session.unwrapKey(
      graphene.MechanismEnum.AES_KEY_WRAP,
      wrappingKey,
      wrapped,
      {
        class: graphene.ObjectClass.SECRET_KEY,
        keyType: graphene.KeyType.AES,
        label: unwrappedKeyLabel,
        token: true,
        private: true,
        sensitive: true,
        encrypt: true,
        decrypt: true,
        extractable: true,
        valueLen: wrapped.length - 8,
      }
    );
    console.log("Key unwrapped successfully:", unwrapped.label, "\n");
  });
})();

