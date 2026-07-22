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
 * - Encrypt/decrypt with CKM_RSA_X_509 (raw RSA). Plaintext must fit in the modulus.
 * - Mirrors JSP EncryptUsing_RSA_X_509.
 */

"use strict";
const { graphene, withSession, usageAndExit, getPlaintext, toHex } = require("./lib/helper");

console.log("\nencrypt_using_rsa_x509.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node encrypt_using_rsa_x509.js <slot_label>",
    "",
    "Example:",
    "node encrypt_using_rsa_x509.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];
(async () => {
  const plaintext = await getPlaintext("Enter plaintext to encrypt : ", 200);
  await withSession(slotLabel, async (session) => {
    const keys = session.generateKeyPair(
      graphene.KeyGenMechanism.RSA,
      {
        keyType: graphene.KeyType.RSA,
        modulusBits: 2048,
        publicExponent: Buffer.from([0x01, 0x00, 0x01]),
        token: false,
        encrypt: true,
      },
      {
        keyType: graphene.KeyType.RSA,
        token: false,
        private: true,
        decrypt: true,
      }
    );
    console.log("RSA-2048 keypair generated.");
    const modulus = keys.publicKey.get("modulus");
    const block = Buffer.alloc(modulus.length, 0);
    const src = Buffer.from(plaintext, "utf8");
    if (src.length >= modulus.length) {
      throw new Error("Plaintext too long for RSA_X_509 block.");
    }
    src.copy(block, modulus.length - src.length);

    const cipher = session.createCipher(graphene.MechanismEnum.RSA_X_509, keys.publicKey);
    let encrypted = cipher.update(block);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    console.log("Plaintext encrypted (RSA_X_509).");

    const decipher = session.createDecipher(graphene.MechanismEnum.RSA_X_509, keys.privateKey);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    const recovered = decrypted.slice(modulus.length - src.length);
    console.log("Encrypted text decrypted.\n");
    console.log("Plain text\t:", plaintext);
    console.log("Encrypted\t:", toHex(encrypted).slice(0, 64) + "...");
    console.log("Recovered\t:", recovered.toString("utf8"));
    console.log();
  });
})();
