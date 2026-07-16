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
 * - ECDH shared-secret derivation (mirrors C CKM_ECDH1_DERIVE_demo).
 */

"use strict";
const { graphene, withSession, usageAndExit } = require("./lib/helper");

console.log("\nderive_ecdh_shared_secret.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node derive_ecdh_shared_secret.js <slot_label>",
    "",
    "Example:",
    "node derive_ecdh_shared_secret.js myPartition\n",
  ]);
}

const slotLabel = process.argv[2];

(async () => {
  await withSession(slotLabel, async (session) => {
    const curve = graphene.NamedCurve.getByName("secp256r1");
    const partyA = session.generateKeyPair(
      graphene.KeyGenMechanism.EC,
      {
        keyType: graphene.KeyType.EC,
        paramsEC: curve.value,
        token: false,
        derive: true,
      },
      {
        keyType: graphene.KeyType.EC,
        token: false,
        private: true,
        derive: true,
      }
    );
    const partyB = session.generateKeyPair(
      graphene.KeyGenMechanism.EC,
      {
        keyType: graphene.KeyType.EC,
        paramsEC: curve.value,
        token: false,
        derive: true,
      },
      {
        keyType: graphene.KeyType.EC,
        token: false,
        private: true,
        derive: true,
      }
    );
    console.log("Two ephemeral ECDH keypairs generated (secp256r1).");

    const peerPoint = partyB.publicKey.get("pointEC");
    const params = new graphene.EcdhParams(graphene.EcKdf.SHA1, null, peerPoint);
    const secret = session.deriveKey(
      { name: graphene.MechanismEnum.ECDH1_DERIVE, params },
      partyA.privateKey,
      {
        class: graphene.ObjectClass.SECRET_KEY,
        keyType: graphene.KeyType.GENERIC_SECRET,
        valueLen: 16,
        token: false,
        encrypt: true,
        decrypt: true,
      }
    );
    console.log("ECDH shared secret derived.");
    console.log("  --> Derived key handle :", secret.handle.toString("hex"));
    console.log();
  });
})();
