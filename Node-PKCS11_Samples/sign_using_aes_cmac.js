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
 * - AES-CMAC sign/verify (mirrors C CKM_AES_CMAC_demo / JSP CMACUsing_AES).
 */

"use strict";
const { graphene, withSession, usageAndExit, getPlaintext, toHex } = require("./lib/helper");

console.log("\nsign_using_aes_cmac.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node sign_using_aes_cmac.js <slot_label>",
    "",
    "Example:",
    "node sign_using_aes_cmac.js myPartition\n",
  ]);
}

const slotLabel = process.argv[2];

(async () => {
  const plaintext = await getPlaintext("Enter plaintext to MAC : ");
  await withSession(slotLabel, async (session) => {
    const key = session.generateKey(graphene.KeyGenMechanism.AES, {
      keyType: graphene.KeyType.AES,
      valueLen: 16,
      token: false,
      sign: true,
      verify: true,
    });
    console.log("AES-128 CMAC key generated.");

    const sign = session.createSign(graphene.MechanismEnum.AES_CMAC, key);
    const mac = sign.once(Buffer.from(plaintext, "utf8"));
    console.log("CMAC computed.");

    const verify = session.createVerify(graphene.MechanismEnum.AES_CMAC, key);
    const ok = verify.once(Buffer.from(plaintext, "utf8"), mac);
    console.log(ok ? "CMAC verified.\n" : "CMAC verification failed.\n");

    console.log("Plain text\t: ", plaintext);
    console.log("CMAC\t\t: ", toHex(mac));
    console.log();
  });
})();
