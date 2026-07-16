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
 * - This sample code demonstrates how to generate an RSA keypair.
 * - It allows you to set your own labels and choose a keypair size.
 * - Public and private keys get distinct labels and attribute templates.
 */

"use strict";
const { graphene, withSession, usageAndExit } = require("./lib/helper");

console.log("\ngenerate_rsa_keypair2.js\n");

if (process.argv.length !== 5) {
  usageAndExit([
    "Usage:",
    "node generate_rsa_keypair2.js <slot_label> <keypair_label> <keysize (BITS)>",
    "",
    "Example:",
    "node generate_rsa_keypair2.js myPartition testRSA 2048\n",
  ]);
}

const slotLabel = process.argv[2];
const keypairLabel = process.argv[3];
const keypairSize = parseInt(process.argv[4], 10);
if (keypairSize < 512 || keypairSize > 8192) {
  console.log("RSA keypair size invalid.\n");
  process.exit(1);
}

(async () => {
  await withSession(slotLabel, async (session) => {
    const keys = session.generateKeyPair(
      graphene.KeyGenMechanism.RSA,
      {
        keyType: graphene.KeyType.RSA,
        modulusBits: keypairSize,
        publicExponent: Buffer.from([0x01, 0x00, 0x01]),
        label: keypairLabel + "-public",
        token: true,
        private: false,
        verify: true,
        encrypt: true,
        wrap: false,
      },
      {
        keyType: graphene.KeyType.RSA,
        label: keypairLabel + "-private",
        token: true,
        private: true,
        sign: true,
        decrypt: true,
        unwrap: false,
        extractable: true,
        modifiable: false,
      }
    );
    console.log("RSA key generated with label : ", keypairLabel);
    console.log("\t > Private Key : ", keys.privateKey.label);
    console.log("\t > Public Key  : ", keys.publicKey.label);
    console.log();
  });
})();

