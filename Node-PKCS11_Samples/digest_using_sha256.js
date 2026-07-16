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
 * - Compute a SHA-256 digest in the HSM (mirrors C CKM_SHA256_demo hashing sample).
 */

"use strict";
const { graphene, withSession, usageAndExit, getPlaintext, toHex } = require("./lib/helper");

console.log("\ndigest_using_sha256.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node digest_using_sha256.js <slot_label>",
    "",
    "Example:",
    "node digest_using_sha256.js myPartition\n",
  ]);
}

const slotLabel = process.argv[2];

(async () => {
  const plaintext = await getPlaintext("Enter data to digest : ");
  await withSession(slotLabel, async (session) => {
    const digest = session.createDigest(graphene.MechanismEnum.SHA256);
    const hash = digest.once(Buffer.from(plaintext, "utf8"));
    console.log("SHA-256 digest computed.\n");
    console.log("Data\t: ", plaintext);
    console.log("Digest\t: ", toHex(hash));
    console.log();
  });
})();
