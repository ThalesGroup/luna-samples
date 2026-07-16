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
 * - This sample code demonstrates how to generate an ECDSA keypair.
 * - The keypair is generated using a user-specified ECC curve.
 */

"use strict";
const { graphene, withSession, usageAndExit } = require("./lib/helper");

console.log("\ngenerate_ecdsa_keypair.js\n");

if (process.argv.length !== 5) {
  usageAndExit([
    "Usage:",
    "node generate_ecdsa_keypair.js <slot_label> <keypair_label> <curve>",
    "",
    "Example:",
    "node generate_ecdsa_keypair.js myPartition testECDSA secp256r1\n",
  ]);
}

const slotLabel = process.argv[2];
const keypairLabel = process.argv[3];
const curveId = process.argv[4];

(async () => {
  await withSession(slotLabel, async (session) => {
    const curve = graphene.NamedCurve.getByName(curveId);
    const keys = session.generateKeyPair(
      graphene.KeyGenMechanism.ECDSA,
      {
        keyType: graphene.KeyType.EC,
        paramsEC: curve.value,
        label: keypairLabel,
        token: true,
        verify: true,
      },
      {
        keyType: graphene.KeyType.EC,
        label: keypairLabel,
        token: true,
        private: true,
        sensitive: true,
        sign: true,
        extractable: true,
      }
    );
    console.log("ECDSA key generated with label : ", keypairLabel);
    console.log("\t > Private Key handle : ", keys.privateKey.handle.toString("hex"));
    console.log("\t > Public Key handle  : ", keys.publicKey.handle.toString("hex"));
    console.log();
  });
})();

