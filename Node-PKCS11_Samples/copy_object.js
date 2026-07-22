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
 * - Copy a session object with C_CopyObject (mirrors C C_CopyObjects_demo).
 */

"use strict";
const { graphene, withSession, usageAndExit } = require("./lib/helper");

console.log("\ncopy_object.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node copy_object.js <slot_label>",
    "",
    "Example:",
    "node copy_object.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];
(async () => {
  await withSession(slotLabel, async (session) => {
    const key = session.generateKey(graphene.KeyGenMechanism.AES, {
      keyType: graphene.KeyType.AES,
      valueLen: 16,
      token: false,
      label: "node-copy-src",
      encrypt: true,
      decrypt: true,
    });
    const copy = session.copy(key, { label: "node-copy-dst", token: false });
    console.log("Source label :", key.get("label"));
    console.log("Copy label   :", copy.get("label"));
    console.log("Copy handle  :", copy.handle.toString("hex"));
    console.log();
  });
})();
