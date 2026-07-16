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
 * - Seed the HSM RNG with C_SeedRandom (mirrors C C_SeedRandom_demo / JSP SeedLunaRNG).
 * - Some Luna Cloud HSM images return CKR_FUNCTION_NOT_SUPPORTED.
 */

"use strict";
const { withSession, seedRandom, usageAndExit, toHex } = require("./lib/helper");

console.log("\nseed_random.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node seed_random.js <slot_label>",
    "",
    "Example:",
    "node seed_random.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];
(async () => {
  await withSession(slotLabel, async (session) => {
    const seed = Buffer.from("Luna-Node-seed-material-0123456789");
    try {
      seedRandom(session, seed);
      console.log("C_SeedRandom succeeded.");
    } catch (e) {
      console.log("C_SeedRandom not supported on this slot:", e.message || e);
      console.log("(Common on some Luna Cloud HSM / Cryptovisor images.)");
    }
    const rnd = session.generateRandom(16);
    console.log("C_GenerateRandom (16 bytes):", toHex(rnd));
    console.log();
  });
})();
