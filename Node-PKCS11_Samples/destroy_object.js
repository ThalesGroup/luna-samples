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
 * - Create a session AES key, then destroy it (mirrors C C_DestroyObject_demo).
 */

"use strict";
const { graphene, withSession, usageAndExit } = require("./lib/helper");

console.log("\ndestroy_object.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node destroy_object.js <slot_label>",
    "",
    "Example:",
    "node destroy_object.js myPartition\n",
  ]);
}

const slotLabel = process.argv[2];

(async () => {
  await withSession(slotLabel, async (session) => {
    const key = session.generateKey(graphene.KeyGenMechanism.AES, {
      keyType: graphene.KeyType.AES,
      valueLen: 16,
      token: false,
      label: "node-destroy-demo",
      encrypt: true,
      decrypt: true,
    });
    console.log("Session AES key created.");
    console.log("  --> handle :", key.handle.toString("hex"));
    key.destroy();
    console.log("Object destroyed.\n");
  });
})();
