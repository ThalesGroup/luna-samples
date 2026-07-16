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
 * - Change an object attribute with C_SetAttributeValue (mirrors C C_SetAttributeValue_demo).
 */

"use strict";
const { graphene, withSession, usageAndExit } = require("./lib/helper");

console.log("\nset_object_attribute.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node set_object_attribute.js <slot_label>",
    "",
    "Example:",
    "node set_object_attribute.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];
(async () => {
  await withSession(slotLabel, async (session) => {
    const key = session.generateKey(graphene.KeyGenMechanism.AES, {
      keyType: graphene.KeyType.AES,
      valueLen: 16,
      token: false,
      modifiable: true,
      label: "node-attr-before",
      encrypt: true,
      decrypt: true,
    });
    console.log("Before label :", key.get("label"));
    key.set({ label: "node-attr-after" });
    console.log("After label  :", key.get("label"));
    console.log();
  });
})();
