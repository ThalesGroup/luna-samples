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
 * - This sample code demonstrates how to generate an RSA keypair and use it for encryption.
 * - It uses RSA_PKCS (PKCS#1 v1.5) mechanism for encryption.
 */

"use strict";
const { graphene, withSession, usageAndExit, getPlaintext, toHex } = require("./lib/helper");

console.log("\nencrypt_using_rsa_pkcs1.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node encrypt_using_rsa_pkcs1.js <slot_label>",
    "",
    "Example:",
    "node encrypt_using_rsa_pkcs1.js myPartition\n",
  ]);
}

const slotLabel = process.argv[2];

(async () => {
  const plaintext = await getPlaintext("Enter plaintext to encrypt : ", 245);
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
    console.log("RSA key generated.");

    const cipher = session.createCipher(graphene.MechanismEnum.RSA_PKCS, keys.publicKey);
    let encrypted = cipher.update(Buffer.from(plaintext, "utf8"));
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    console.log("Plaintext encrypted.");

    const decipher = session.createDecipher(graphene.MechanismEnum.RSA_PKCS, keys.privateKey);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    console.log("Encrypted data decrypted.\n");

    console.log("Plain text\t: ", plaintext);
    console.log("Plain text (hex): ", Buffer.from(plaintext, "utf8").toString("hex"));
    console.log("Encrypted text\t: ", toHex(encrypted));
    console.log("Decrypted text  : ", toHex(decrypted));
    console.log();
  });
})();

