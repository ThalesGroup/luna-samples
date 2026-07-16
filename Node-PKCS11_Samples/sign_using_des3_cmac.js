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
 * - DES3-CMAC sign/verify (mirrors JSP CMACUsing_DES3).
 * - May fail on FIPS-mode partitions.
 */

"use strict";
const {
  graphene,
  withSession,
  usageAndExit,
  getPlaintext,
  toHex,
  CKM_DES3_CMAC,
} = require("./lib/helper");

console.log("\nsign_using_des3_cmac.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node sign_using_des3_cmac.js <slot_label>",
    "",
    "Example:",
    "node sign_using_des3_cmac.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];
(async () => {
  const plaintext = await getPlaintext("Enter plaintext to MAC : ");
  await withSession(slotLabel, async (session) => {
    const key = session.generateKey(graphene.MechanismEnum.DES3_KEY_GEN, {
      keyType: graphene.KeyType.DES3,
      token: false,
      sign: true,
      verify: true,
    });
    console.log("DES3 CMAC key generated.");
    const alg = { name: CKM_DES3_CMAC };
    const mac = session.createSign(alg, key).once(Buffer.from(plaintext, "utf8"));
    console.log("CMAC computed.");
    const ok = session
      .createVerify(alg, key)
      .once(Buffer.from(plaintext, "utf8"), mac);
    console.log(ok ? "CMAC verified.\n" : "CMAC verification failed.\n");
    console.log("Plain text\t: ", plaintext);
    console.log("CMAC\t\t: ", toHex(mac));
    console.log();
  });
})();
