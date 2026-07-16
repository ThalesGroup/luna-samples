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
 * - Generate an Ed25519 (Edwards) keypair (mirrors C CKM_EC_EDWARDS_KEY_PAIR_GEN_demo).
 * - Not FIPS-approved; FIPS partitions may return CKR_MECHANISM_INVALID.
 */

"use strict";
const {
  graphene,
  withSession,
  usageAndExit,
  CKM_EC_EDWARDS_KEY_PAIR_GEN,
  CKK_EC_EDWARDS,
  ED25519_EC_PARAMS,
} = require("./lib/helper");

console.log("\ngenerate_eddsa_keypair.js\n");
if (process.argv.length !== 4) {
  usageAndExit([
    "Usage:",
    "node generate_eddsa_keypair.js <slot_label> <keypair_label>",
    "",
    "Example:",
    "node generate_eddsa_keypair.js myPartition myEd25519\n",
  ]);
}
const [slotLabel, keyLabel] = process.argv.slice(2);
(async () => {
  await withSession(slotLabel, async (session) => {
    const keys = session.generateKeyPair(
      { name: CKM_EC_EDWARDS_KEY_PAIR_GEN },
      {
        class: graphene.ObjectClass.PUBLIC_KEY,
        keyType: CKK_EC_EDWARDS,
        paramsEC: ED25519_EC_PARAMS,
        label: keyLabel,
        token: true,
        private: true,
        verify: true,
      },
      {
        class: graphene.ObjectClass.PRIVATE_KEY,
        keyType: CKK_EC_EDWARDS,
        label: keyLabel,
        token: true,
        private: true,
        sensitive: true,
        extractable: false,
        sign: true,
      }
    );
    console.log("Ed25519 keypair generated with label : ", keyLabel);
    console.log(
      "\t > Private Key handle : ",
      keys.privateKey.handle.toString("hex")
    );
    console.log(
      "\t > Public Key handle  : ",
      keys.publicKey.handle.toString("hex")
    );
    console.log();
  });
})();
