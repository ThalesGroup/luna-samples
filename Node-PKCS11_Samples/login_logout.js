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
 * - This code uses the high-level PKCS#11 API to demonstrate how to login
 *   as a crypto-officer (CKU_USER) and logout.
 */

"use strict";
const { withSession, usageAndExit } = require("./lib/helper");

console.log("\nlogin_logout.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "usage :-",
    "node login_logout.js <slot_label>",
    "",
    "Example:",
    "node login_logout.js myPartition",
    "",
    "Set LUNA_PIN for the Crypto Officer password (or you will be prompted).",
    "",
  ]);
}

const slotLabel = process.argv[2];

(async () => {
  await withSession(slotLabel, async () => {
    console.log("Logout success.\n");
  });
})();

