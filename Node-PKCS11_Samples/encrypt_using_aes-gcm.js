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
 * - Encrypt/decrypt with AES-GCM (mirrors C CKM_AES_GCM / JSP EncryptUsing_AESGCM).
 * - Uses graphene AesGcm240Params (Luna-compatible GCM parameter layout).
 */

"use strict";
const { graphene, withSession, usageAndExit, getPlaintext, toHex } = require("./lib/helper");

console.log("\nencrypt_using_aes-gcm.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node encrypt_using_aes-gcm.js <slot_label>",
    "",
    "Example:",
    "node encrypt_using_aes-gcm.js myPartition\n",
  ]);
}

const slotLabel = process.argv[2];

(async () => {
  const plaintext = await getPlaintext("Enter plaintext to encrypt : ");
  await withSession(slotLabel, async (session) => {
    const secretKey = session.generateKey(graphene.KeyGenMechanism.AES, {
      keyType: graphene.KeyType.AES,
      valueLen: 16,
      token: false,
      encrypt: true,
      decrypt: true,
    });
    console.log("AES-128 key generated.");

    const iv = session.generateRandom(12);
    const aad = Buffer.from("Luna-Node-AAD");
    const alg = {
      name: graphene.MechanismEnum.AES_GCM,
      // Luna expects the older GCM params layout exposed as AesGcm240Params.
      params: new graphene.AesGcm240Params(iv, aad, 128),
    };

    // Luna AES-GCM is single-part only (C_Encrypt / C_Decrypt); Update is unsupported.
    const pt = Buffer.from(plaintext, "utf8");
    const encBuf = Buffer.alloc(pt.length + 64);
    const encrypted = session.createCipher(alg, secretKey).once(pt, encBuf);
    console.log("Plaintext encrypted (AES-GCM).");

    const decBuf = Buffer.alloc(encrypted.length);
    const decrypted = session.createDecipher(alg, secretKey).once(encrypted, decBuf);
    console.log("Encrypted text decrypted.\n");

    console.log("Plain text\t: ", plaintext);
    console.log("IV (hex)\t: ", toHex(iv));
    console.log("AAD\t\t: ", aad.toString());
    console.log("Cipher+tag\t: ", toHex(encrypted));
    console.log("Decrypted\t: ", decrypted.toString("utf8"));
    console.log();
  });
})();
