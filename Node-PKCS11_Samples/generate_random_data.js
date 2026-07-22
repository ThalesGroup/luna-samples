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
 * - This sample demonstrates how to generate random data.
 */

"use strict";
const { withSession, usageAndExit, toHex } = require("./lib/helper");

console.log("\ngenerate_random_data.js\n");

if (process.argv.length !== 4) {
  usageAndExit([
    "Usage:",
    "node generate_random_data.js <slot_label> <data_size (bytes)>",
    "",
    "Example:",
    "node generate_random_data.js myPartition 32\n",
  ]);
}

const slotLabel = process.argv[2];
const dataSize = parseInt(process.argv[3], 10);

(async () => {
  await withSession(slotLabel, async (session) => {
    const randomData = session.generateRandom(dataSize);
    console.log(dataSize, "bytes of random data generated.");
    console.log("Random Data (hex) :", toHex(randomData));
    console.log();
  });
})();

