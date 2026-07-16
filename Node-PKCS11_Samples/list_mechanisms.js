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
 * - List mechanisms available on a slot (mirrors C C_GetMechanismList_Demo).
 */

"use strict";
const { graphene, requireP11Lib, findSlotByLabel, usageAndExit } = require("./lib/helper");
const { mechanismName } = require("./lib/mechanism_names");

console.log("\nlist_mechanisms.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node list_mechanisms.js <slot_label>",
    "",
    "Example:",
    "node list_mechanisms.js myPartition\n",
  ]);
}

const slotLabel = process.argv[2];

(async () => {
  const pkcs11Library = requireP11Lib();
  const mod = graphene.Module.load(pkcs11Library, "Luna");
  mod.initialize();
  try {
    console.log("PKCS11 library found at : ", pkcs11Library);
    const slot = findSlotByLabel(mod, slotLabel);
    if (!slot) {
      console.log("Incorrect token label.\n");
      process.exitCode = 1;
      return;
    }
    const mechs = slot.getMechanisms();
    console.log("Token :", slotLabel);
    console.log("Mechanisms available :", mechs.length, "\n");
    console.log(
      "NAME".padEnd(42),
      "ID".padEnd(12),
      "MIN",
      "MAX",
      "FLAGS"
    );
    for (let i = 0; i < mechs.length; i++) {
      const m = mechs.items(i);
      const id = Number(m.type) >>> 0;
      const name = mechanismName(id, m.name);
      console.log(
        name.padEnd(42),
        ("0x" + id.toString(16)).padEnd(12),
        String(m.minKeySize).padStart(4),
        String(m.maxKeySize).padStart(4),
        "0x" + Number(m.flags).toString(16)
      );
    }
    console.log();
  } finally {
    try {
      mod.finalize();
    } catch (_) {
      /* ignore */
    }
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
