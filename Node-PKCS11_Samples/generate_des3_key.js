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
 * - Generate a DES3 key (mirrors C CKM_DES3_KEY_GEN_demo / JSP GenerateDES3Key).
 */

"use strict";
const { graphene, withSession, usageAndExit } = require("./lib/helper");

console.log("\ngenerate_des3_key.js\n");

if (process.argv.length !== 4) {
  usageAndExit([
    "Usage:",
    "node generate_des3_key.js <slot_label> <key_label>",
    "",
    "Example:",
    "node generate_des3_key.js myPartition myDes3Key\n",
  ]);
}

const slotLabel = process.argv[2];
const keyLabel = process.argv[3];

(async () => {
  await withSession(slotLabel, async (session) => {
    const key = session.generateKey(graphene.MechanismEnum.DES3_KEY_GEN, {
      keyType: graphene.KeyType.DES3,
      label: keyLabel,
      token: true,
      private: true,
      sensitive: true,
      encrypt: true,
      decrypt: true,
    });
    console.log("DES3 key generated with label : ", keyLabel);
    console.log("\t > handle : ", key.handle.toString("hex"));
    console.log();
  });
})();
