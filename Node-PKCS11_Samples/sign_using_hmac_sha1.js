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
 * - HMAC-SHA1 sign/verify (mirrors JSP HMACUsing_SHA1).
 */

"use strict";
const { graphene, withSession, usageAndExit, getPlaintext, toHex } = require("./lib/helper");

console.log("\nsign_using_hmac_sha1.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node sign_using_hmac_sha1.js <slot_label>",
    "",
    "Example:",
    "node sign_using_hmac_sha1.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];
(async () => {
  const plaintext = await getPlaintext("Enter plaintext to HMAC : ");
  await withSession(slotLabel, async (session) => {
    const key = session.generateKey(graphene.KeyGenMechanism.GENERIC_SECRET, {
      keyType: graphene.KeyType.GENERIC_SECRET,
      valueLen: 20,
      token: false,
      sign: true,
      verify: true,
    });
    console.log("GENERIC_SECRET HMAC key generated.");
    const mac = session
      .createSign(graphene.MechanismEnum.SHA_1_HMAC, key)
      .once(Buffer.from(plaintext, "utf8"));
    console.log("HMAC-SHA1 computed.");
    const ok = session
      .createVerify(graphene.MechanismEnum.SHA_1_HMAC, key)
      .once(Buffer.from(plaintext, "utf8"), mac);
    console.log(ok ? "HMAC verified.\n" : "HMAC verification failed.\n");
    console.log("Plain text\t:", plaintext);
    console.log("HMAC\t\t:", toHex(mac));
    console.log();
  });
})();
