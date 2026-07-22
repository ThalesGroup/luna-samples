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
 * - Sign/verify with SHA1_RSA_X9_31 (mirrors JSP SignUsing_RSA_X9_31).
 */

"use strict";
const { graphene, withSession, usageAndExit, getPlaintext, toHex } = require("./lib/helper");

console.log("\nsign_using_rsa_x9_31.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node sign_using_rsa_x9_31.js <slot_label>",
    "",
    "Example:",
    "node sign_using_rsa_x9_31.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];
(async () => {
  const plaintext = await getPlaintext("Enter plaintext to sign : ", 100);
  await withSession(slotLabel, async (session) => {
    const keys = session.generateKeyPair(
      graphene.KeyGenMechanism.RSA,
      {
        keyType: graphene.KeyType.RSA,
        modulusBits: 2048,
        publicExponent: Buffer.from([0x01, 0x00, 0x01]),
        token: false,
        verify: true,
      },
      {
        keyType: graphene.KeyType.RSA,
        token: false,
        private: true,
        sign: true,
      }
    );
    console.log("RSA-2048 keypair generated.");
    const sign = session.createSign(
      graphene.MechanismEnum.SHA1_RSA_X9_31,
      keys.privateKey
    );
    const signature = sign.once(Buffer.from(plaintext, "utf8"));
    console.log("Plaintext signed.");
    const verify = session.createVerify(
      graphene.MechanismEnum.SHA1_RSA_X9_31,
      keys.publicKey
    );
    const ok = verify.once(Buffer.from(plaintext, "utf8"), signature);
    console.log(ok ? "Signature verified.\n" : "Signature verification failed.\n");
    console.log("Plain text\t: ", plaintext);
    console.log("Signature\t: ", toHex(signature));
    console.log();
  });
})();
