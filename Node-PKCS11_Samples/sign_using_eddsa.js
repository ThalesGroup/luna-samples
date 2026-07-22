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
 * - Generate a session Ed25519 keypair and sign/verify with CKM_EDDSA.
 */

"use strict";
const {
  graphene,
  withSession,
  usageAndExit,
  getPlaintext,
  toHex,
  CKM_EC_EDWARDS_KEY_PAIR_GEN,
  CKM_EDDSA,
  CKK_EC_EDWARDS,
  ED25519_EC_PARAMS,
} = require("./lib/helper");

console.log("\nsign_using_eddsa.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node sign_using_eddsa.js <slot_label>",
    "",
    "Example:",
    "node sign_using_eddsa.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];
(async () => {
  const plaintext = await getPlaintext("Enter plaintext to sign : ");
  await withSession(slotLabel, async (session) => {
    const keys = session.generateKeyPair(
      { name: CKM_EC_EDWARDS_KEY_PAIR_GEN },
      {
        class: graphene.ObjectClass.PUBLIC_KEY,
        keyType: CKK_EC_EDWARDS,
        paramsEC: ED25519_EC_PARAMS,
        token: false,
        private: true,
        verify: true,
      },
      {
        class: graphene.ObjectClass.PRIVATE_KEY,
        keyType: CKK_EC_EDWARDS,
        token: false,
        private: true,
        sensitive: true,
        sign: true,
      }
    );
    console.log("Ed25519 session keypair generated.");
    const signature = session
      .createSign({ name: CKM_EDDSA }, keys.privateKey)
      .once(Buffer.from(plaintext, "utf8"));
    console.log("Plaintext signed.");
    const ok = session
      .createVerify({ name: CKM_EDDSA }, keys.publicKey)
      .once(Buffer.from(plaintext, "utf8"), signature);
    console.log(ok ? "Signature verified.\n" : "Signature verification failed.\n");
    console.log("Plain text\t: ", plaintext);
    console.log("Signature\t: ", toHex(signature));
    console.log();
  });
})();
