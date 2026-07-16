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
 * - Read common attributes from a key (mirrors C C_GetAttributeValue / JSP DisplayAttributes).
 */

"use strict";
const { graphene, withSession, usageAndExit } = require("./lib/helper");

console.log("\nget_object_attributes.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node get_object_attributes.js <slot_label>",
    "",
    "Example:",
    "node get_object_attributes.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];
(async () => {
  await withSession(slotLabel, async (session) => {
    const key = session.generateKey(graphene.KeyGenMechanism.AES, {
      keyType: graphene.KeyType.AES,
      valueLen: 16,
      token: false,
      label: "node-attrs",
      encrypt: true,
      decrypt: true,
      wrap: true,
      extractable: true,
    });
    const attrs = [
      "class",
      "keyType",
      "label",
      "token",
      "private",
      "sensitive",
      "extractable",
      "encrypt",
      "decrypt",
      "wrap",
      "unwrap",
    ];
    console.log("Attributes for", key.get("label"));
    for (const a of attrs) {
      try {
        console.log("  ", a.padEnd(14), ":", key.get(a));
      } catch (_) {
        console.log("  ", a.padEnd(14), ":", "(unavailable)");
      }
    }
    console.log();
  });
})();
