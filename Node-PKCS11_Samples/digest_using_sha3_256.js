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
 * - Compute a SHA3-256 digest (mirrors C CKM_SHA3_256_demo).
 */

"use strict";
const {
  withSession,
  usageAndExit,
  getPlaintext,
  toHex,
  CKM_SHA3_256,
} = require("./lib/helper");

console.log("\ndigest_using_sha3_256.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node digest_using_sha3_256.js <slot_label>",
    "",
    "Example:",
    "node digest_using_sha3_256.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];
(async () => {
  const plaintext = await getPlaintext("Enter data to digest : ");
  await withSession(slotLabel, async (session) => {
    const hash = session
      .createDigest({ name: CKM_SHA3_256 })
      .once(Buffer.from(plaintext, "utf8"));
    console.log("SHA3-256 digest computed.\n");
    console.log("Data\t: ", plaintext);
    console.log("Digest\t: ", toHex(hash));
    console.log();
  });
})();
