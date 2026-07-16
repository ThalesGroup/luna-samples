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
 * - Login as Crypto User (CKU_CRYPTO_USER) (mirrors C Crypto_User_Login / JSP LoginUsingCryptoUser).
 * - Requires a Crypto User PIN on the partition (env LUNA_CU_PIN).
 */

"use strict";
const { withSession, CKU_CRYPTO_USER, usageAndExit } = require("./lib/helper");

console.log("\nlogin_crypto_user.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node login_crypto_user.js <slot_label>",
    "",
    "Set LUNA_CU_PIN for the Crypto User password (or you will be prompted).",
    "",
    "Example:",
    "node login_crypto_user.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];
(async () => {
  await withSession(
    slotLabel,
    async () => {
      console.log("Logged in as Crypto User (CKU_CRYPTO_USER).");
      console.log("Logout success.\n");
    },
    { userType: CKU_CRYPTO_USER }
  );
})();
