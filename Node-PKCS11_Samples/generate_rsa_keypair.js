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
 */

"use strict";
const { graphene, withSession, usageAndExit } = require("./lib/helper");

console.log("\ngenerate_rsa_keypair.js\n");

if (process.argv.length !== 5) {
  usageAndExit([
    "Usage:",
    "node generate_rsa_keypair.js <slot_label> <keypair_label> <keysize (BITS)>",
    "",
    "Example:",
    "node generate_rsa_keypair.js myPartition testRSA 2048\n",
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
        label: keypairLabel,
        token: true,
        verify: true,
        encrypt: true,
        wrap: true,
      },
      {
        keyType: graphene.KeyType.RSA,
        label: keypairLabel,
        token: true,
        private: true,
        sensitive: true,
        sign: true,
        decrypt: true,
        unwrap: true,
        extractable: true,
      }
    );
    console.log("RSA key generated with label : ", keypairLabel);
    console.log("\t > Private Key handle : ", keys.privateKey.handle.toString("hex"));
    console.log("\t > Public Key handle  : ", keys.publicKey.handle.toString("hex"));
    console.log();
  });
})();

