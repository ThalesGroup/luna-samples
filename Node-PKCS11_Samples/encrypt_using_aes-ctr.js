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
 * - Encrypt/decrypt with AES-CTR (mirrors C CKM_AES_CTR_demo / JSP EncryptUsing_AESCTRMode).
 * - graphene-pk11 has no AesCtrParams helper; pass a packed CK_AES_CTR_PARAMS Buffer.
 */

"use strict";
const {
  graphene,
  withSession,
  usageAndExit,
  getPlaintext,
  toHex,
  ulong,
} = require("./lib/helper");

console.log("\nencrypt_using_aes-ctr.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node encrypt_using_aes-ctr.js <slot_label>",
    "",
    "Example:",
    "node encrypt_using_aes-ctr.js myPartition\n",
  ]);
}

const slotLabel = process.argv[2];

/** Pack CK_AES_CTR_PARAMS: CK_ULONG ulCounterBits + CK_BYTE cb[16]. */
function aesCtrParams(iv16, counterBits = 128) {
  return Buffer.concat([ulong(counterBits), Buffer.from(iv16).subarray(0, 16)]);
}

(async () => {
  const plaintext = await getPlaintext("Enter plaintext to encrypt : ");
  await withSession(slotLabel, async (session) => {
    const secretKey = session.generateKey(graphene.KeyGenMechanism.AES, {
      keyType: graphene.KeyType.AES,
      valueLen: 32,
      token: false,
      encrypt: true,
      decrypt: true,
    });
    console.log("AES-256 key generated.");

    const iv = session.generateRandom(16);
    const alg = {
      name: graphene.MechanismEnum.AES_CTR,
      params: aesCtrParams(iv, 128),
    };

    const cipher = session.createCipher(alg, secretKey);
    let encrypted = cipher.update(Buffer.from(plaintext, "utf8"));
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    console.log("Plaintext encrypted (AES-CTR).");

    const decipher = session.createDecipher(alg, secretKey);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    console.log("Encrypted text decrypted.\n");

    console.log("Plain text\t: ", plaintext);
    console.log("IV/counter\t: ", toHex(iv));
    console.log("Encrypted\t: ", toHex(encrypted));
    console.log("Decrypted\t: ", decrypted.toString("utf8"));
    console.log();
  });
})();
