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
 * - Show C_GetMechanismInfo for a named mechanism (mirrors C C_GetMechanismInfo_demo).
 */

"use strict";
const { graphene, requireP11Lib, findSlotByLabel, usageAndExit } = require("./lib/helper");

console.log("\nget_mechanism_info.js\n");
if (process.argv.length !== 4) {
  usageAndExit([
    "Usage:",
    "node get_mechanism_info.js <slot_label> <MECHANISM_NAME>",
    "",
    "Example:",
    "node get_mechanism_info.js myPartition AES_GCM\n",
  ]);
}
const slotLabel = process.argv[2];
const mechName = process.argv[3].toUpperCase();
(async () => {
  const lib = requireP11Lib();
  const mod = graphene.Module.load(lib, "Luna");
  mod.initialize();
  try {
    const slot = findSlotByLabel(mod, slotLabel);
    if (!slot) {
      console.log("Incorrect token label.");
      process.exitCode = 1;
      return;
    }
    const mechType = graphene.MechanismEnum[mechName];
    if (mechType == null) {
      console.log("Unknown mechanism name:", mechName);
      process.exitCode = 1;
      return;
    }
    const mechs = slot.getMechanisms();
    let found = null;
    for (let i = 0; i < mechs.length; i++) {
      const m = mechs.items(i);
      if (m.type === mechType || m.name === mechName) {
        found = m;
        break;
      }
    }
    if (!found) {
      console.log(mechName, "not advertised on this slot.");
      process.exitCode = 1;
      return;
    }
    console.log("Mechanism :", found.name);
    console.log("  minKeySize :", found.minKeySize);
    console.log("  maxKeySize :", found.maxKeySize);
    console.log("  flags      : 0x" + Number(found.flags).toString(16));
    console.log();
  } finally {
    try {
      mod.finalize();
    } catch (_) {}
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
