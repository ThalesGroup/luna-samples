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
 * - Compute a SHAKE-256 XOF digest (mirrors C CKM_SHAKE_256_demo).
 * - Uses Luna vendor CKM_SHAKE_256 (0x80000f01) with a 4-byte output-length param.
 */

"use strict";
const {
  withSession,
  usageAndExit,
  getPlaintext,
  toHex,
  CKM_SHAKE_256,
  u32,
} = require("./lib/helper");

console.log("\ndigest_using_shake_256.js\n");
if (process.argv.length < 3 || process.argv.length > 4) {
  usageAndExit([
    "Usage:",
    "node digest_using_shake_256.js <slot_label> [output_len]",
    "",
    "Example:",
    "node digest_using_shake_256.js myPartition 50\n",
  ]);
}
const slotLabel = process.argv[2];
const outLen = parseInt(process.argv[3] || "50", 10);
(async () => {
  const plaintext = await getPlaintext("Enter data to digest : ");
  await withSession(slotLabel, async (session) => {
    // Mechanism param is CK_ULONG (platform width via u32/ulong helper).
    const hash = session
      .createDigest({ name: CKM_SHAKE_256, params: u32(outLen) })
      .once(Buffer.from(plaintext, "utf8"));
    console.log("SHAKE-256 digest computed.\n");
    console.log("Data\t: ", plaintext);
    console.log("Length\t: ", hash.length);
    console.log("Digest\t: ", toHex(hash));
    console.log();
  });
})();
