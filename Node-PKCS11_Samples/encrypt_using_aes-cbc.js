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
 * - This sample code demonstrates how to use a generated AES-128 key to encrypt a plaintext.
 * - For encryption, this sample uses AES_CBC mechanism.
 * - Note: plaintext length must be a multiple of the AES block size (16) for AES_CBC.
 */

"use strict";
const { graphene, withSession, usageAndExit, getPlaintext, toHex } = require("./lib/helper");

console.log("\nencrypt_using_aes-cbc.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node encrypt_using_aes-cbc.js <slot_label>",
    "",
    "Example:",
    "node encrypt_using_aes-cbc.js myPartition\n",
  ]);
}

const slotLabel = process.argv[2];

(async () => {
  let plaintext = await getPlaintext("Enter plaintext to encrypt : ");
  // AES_CBC (no pad) requires a multiple of 16 bytes — pad for the demo if needed.
  const len = Buffer.byteLength(plaintext, "utf8");
  if (len % 16 !== 0) {
    plaintext = plaintext + " ".repeat(16 - (len % 16));
    console.log("(padded plaintext to AES block boundary for AES_CBC demo)");
  }

  await withSession(slotLabel, async (session) => {
    const secretKey = session.generateKey(graphene.KeyGenMechanism.AES, {
      keyType: graphene.KeyType.AES,
      valueLen: 16,
      token: false,
      encrypt: true,
      decrypt: true,
    });
    console.log("AES-128 key generated.");

    const iv = session.generateRandom(16);
    const alg = {
      name: graphene.MechanismEnum.AES_CBC,
      params: new graphene.AesCbcParams(iv),
    };

    const cipher = session.createCipher(alg, secretKey);
    let encrypted = cipher.update(Buffer.from(plaintext, "utf8"));
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    console.log("Plaintext encrypted.");

    const decipher = session.createDecipher(alg, secretKey);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    console.log("Encrypted text decrypted.\n");

    console.log("Plain text\t: ", plaintext);
    console.log("Plain text (hex): ", Buffer.from(plaintext, "utf8").toString("hex"));
    console.log("Encrypted text\t: ", toHex(encrypted));
    console.log("Decrypted text\t: ", toHex(decrypted));
    console.log();
  });
})();

