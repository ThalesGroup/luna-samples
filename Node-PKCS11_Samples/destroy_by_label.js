#!/usr/bin/env node
/*
 * Destroy every token object carrying one of the given labels.
 *
 * Usage: node destroy_by_label.js <slot_label> <obj_label> [<obj_label> ...]
 *        (PIN from LUNA_PIN, library from P11_LIB)
 */
"use strict";
const graphene = require("graphene-pk11");

const slotLabel = process.argv[2];
const labels = process.argv.slice(3);
const pin = process.env.LUNA_PIN;
const libPath = process.env.P11_LIB;

if (!slotLabel || labels.length === 0 || !pin || !libPath) {
  console.error("need <slot_label> <obj_label>... plus LUNA_PIN and P11_LIB");
  process.exit(1);
}

const mod = graphene.Module.load(libPath, "Luna");
mod.initialize();
let session;
try {
  const slots = mod.getSlots(true);
  let slot = null;
  for (let i = 0; i < slots.length; i++) {
    if (slots.items(i).getToken().label.trim() === slotLabel) {
      slot = slots.items(i);
      break;
    }
  }
  if (!slot) throw new Error("slot not found: " + slotLabel);

  session = slot.open(
    graphene.SessionFlag.RW_SESSION | graphene.SessionFlag.SERIAL_SESSION
  );
  session.login(pin, graphene.UserType.USER);

  for (const label of labels) {
    const found = session.find({ label });
    if (found.length === 0) {
      console.log(`absent : ${label}`);
      continue;
    }
    for (let i = 0; i < found.length; i++) {
      session.destroy(found.items(i));
    }
    console.log(`removed: ${label} (${found.length})`);
  }
} catch (err) {
  console.error("destroy failed:", err.message || err);
  process.exitCode = 1;
} finally {
  if (session) {
    try { session.logout(); } catch (_) {}
    try { session.close(); } catch (_) {}
  }
  try { mod.finalize(); } catch (_) {}
}
