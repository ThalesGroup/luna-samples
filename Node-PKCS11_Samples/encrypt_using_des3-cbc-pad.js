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
 * - Encrypt/decrypt with DES3-CBC-PAD (mirrors C CKM_DES3_CBC_PAD / JSP DES3 samples).
 */

"use strict";
const { graphene, withSession, usageAndExit, getPlaintext, toHex } = require("./lib/helper");

console.log("\nencrypt_using_des3-cbc-pad.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node encrypt_using_des3-cbc-pad.js <slot_label>",
    "",
    "Example:",
    "node encrypt_using_des3-cbc-pad.js myPartition\n",
  ]);
}

const slotLabel = process.argv[2];

(async () => {
  const plaintext = await getPlaintext("Enter plaintext to encrypt : ");
  await withSession(slotLabel, async (session) => {
    const secretKey = session.generateKey(graphene.MechanismEnum.DES3_KEY_GEN, {
      keyType: graphene.KeyType.DES3,
      token: false,
      encrypt: true,
      decrypt: true,
    });
    console.log("DES3 key generated.");

    const iv = session.generateRandom(8);
    const alg = {
      name: graphene.MechanismEnum.DES3_CBC_PAD,
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
    console.log("Encrypted\t: ", toHex(encrypted));
    console.log("Decrypted\t: ", decrypted.toString("utf8"));
    console.log();
  });
})();
