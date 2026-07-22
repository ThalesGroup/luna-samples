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
 * - Create a CKO_DATA object (mirrors C C_CreateObject_demo).
 */

"use strict";
const { graphene, withSession, usageAndExit } = require("./lib/helper");

console.log("\ncreate_data_object.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node create_data_object.js <slot_label>",
    "",
    "Example:",
    "node create_data_object.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];
(async () => {
  await withSession(slotLabel, async (session) => {
    const obj = session.create({
      class: graphene.ObjectClass.DATA,
      token: false,
      private: false,
      label: "data object",
      value: Buffer.from("01123581321345589"),
    });
    console.log("Data object created.");
    console.log("  --> handle :", obj.handle.toString("hex"));
    console.log("  --> label  :", obj.label);
    obj.destroy();
    console.log("Data object destroyed.\n");
  });
})();
