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
 * - This code demonstrates how to enumerate "Token Ready" slots.
 */

"use strict";
const { graphene, requireP11Lib } = require("./lib/helper");

console.log("\nenumerate_slots.js\n");

const pkcs11Library = requireP11Lib();
if (!process.env.P11_LIB) {
  console.log("*** P11_LIB environment variable not set — using default. ***");
  console.log("> set P11_LIB=" + pkcs11Library + "\n");
}

const mod = graphene.Module.load(pkcs11Library, "Luna");
mod.initialize();
try {
  const slots = mod.getSlots(true);
  if (!slots.length) {
    console.log("No slots were found.\n");
    process.exit(0);
  }
  console.log();
  for (let i = 0; i < slots.length; i++) {
    const slot = slots.items(i);
    const slotId = Buffer.isBuffer(slot.handle)
      ? slot.handle.readUInt32LE(0)
      : Number(slot.handle);
    console.log("Slot ID:", slotId);
    console.log("  Description:", String(slot.slotDescription).trim());
    console.log("  Manufacturer:", String(slot.manufacturerID).trim());
    console.log(
      "  Hardware:",
      slot.hardwareVersion.major + "." + slot.hardwareVersion.minor
    );
    console.log(
      "  Firmware:",
      slot.firmwareVersion.major + "." + slot.firmwareVersion.minor
    );
    console.log("  Flags:", slot.flags);
    try {
      const token = slot.getToken();
      console.log("  Token label:", String(token.label).trim());
      console.log("  Token serial:", String(token.serialNumber).trim());
      console.log("  Token manufacturer:", String(token.manufacturerID).trim());
      console.log("  Token model:", String(token.model).trim());
    } catch (e) {
      console.log("  (no token:", e.message + ")");
    }
    console.log("-----------------\n");
  }
} finally {
  mod.finalize();
}

