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
 * - HMAC-SHA256 sign/verify (mirrors C CKM_SHA256_HMAC_demo / JSP HMACUsing_SHA256).
 */

"use strict";
const { graphene, withSession, usageAndExit, getPlaintext, toHex } = require("./lib/helper");

console.log("\nsign_using_hmac_sha256.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node sign_using_hmac_sha256.js <slot_label>",
    "",
    "Example:",
    "node sign_using_hmac_sha256.js myPartition\n",
  ]);
}

const slotLabel = process.argv[2];

(async () => {
  const plaintext = await getPlaintext("Enter plaintext to HMAC : ");
  await withSession(slotLabel, async (session) => {
    const key = session.generateKey(graphene.KeyGenMechanism.GENERIC_SECRET, {
      keyType: graphene.KeyType.GENERIC_SECRET,
      valueLen: 32,
      token: false,
      sign: true,
      verify: true,
    });
    console.log("GENERIC_SECRET HMAC key generated.");

    const sign = session.createSign(graphene.MechanismEnum.SHA256_HMAC, key);
    const mac = sign.once(Buffer.from(plaintext, "utf8"));
    console.log("HMAC-SHA256 computed.");

    const verify = session.createVerify(graphene.MechanismEnum.SHA256_HMAC, key);
    const ok = verify.once(Buffer.from(plaintext, "utf8"), mac);
    console.log(ok ? "HMAC verified.\n" : "HMAC verification failed.\n");

    console.log("Plain text\t: ", plaintext);
    console.log("HMAC\t\t: ", toHex(mac));
    console.log();
  });
})();
