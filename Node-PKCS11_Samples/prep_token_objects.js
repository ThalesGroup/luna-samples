#!/usr/bin/env node
/*
 * Create the token objects that several C samples expect to already exist.
 *
 * C_CreateObject_demo and CKM_AES_KEY_GEN_demo build their objects with
 * CKA_TOKEN=FALSE, so the objects die with the process. C_GetAttributeValue_demo,
 * C_SetAttributeValue_demo and Wrap_PQC_PrivateKey_demo then look for those same
 * labels in a fresh process and find nothing. Seed persistent equivalents once.
 *
 * Usage: node prep_token_objects.js <slot_label>   (PIN from LUNA_PIN)
 */
"use strict";
const graphene = require("graphene-pk11");

const slotLabel = process.argv[2];
const pin = process.env.LUNA_PIN;
const libPath = process.env.P11_LIB;

if (!slotLabel || !pin || !libPath) {
  console.error("need <slot_label> plus LUNA_PIN and P11_LIB");
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

  // C_SetAttributeValue_demo renames "data object" to "renamed object", so a
  // second run would find nothing. Clear the renamed leftover first.
  const stale = session.find({
    class: graphene.ObjectClass.DATA,
    label: "renamed object",
  });
  for (let i = 0; i < stale.length; i++) {
    session.destroy(stale.items(i));
    console.log("removed: renamed object");
  }

  const wanted = [
    {
      label: "data object",
      find: { class: graphene.ObjectClass.DATA, label: "data object" },
      create: () =>
        session.create({
          class: graphene.ObjectClass.DATA,
          token: true,
          private: false,
          modifiable: true,
          label: "data object",
          value: Buffer.from("01123581321345589"),
        }),
    },
    {
      label: "MyAESKey",
      find: { class: graphene.ObjectClass.SECRET_KEY, label: "MyAESKey" },
      needs: (obj) => obj.get("derive") === true,
      create: () =>
        session.generateKey(graphene.MechanismEnum.AES_KEY_GEN, {
          class: graphene.ObjectClass.SECRET_KEY,
          keyType: graphene.KeyType.AES,
          valueLen: 32,
          token: true,
          private: true,
          sensitive: true,
          extractable: true,
          modifiable: true,
          label: "MyAESKey",
          encrypt: true,
          decrypt: true,
          wrap: true,
          unwrap: true,
          // CKM_NIST_PRF_KDF_demo takes this key as its KDF base key.
          derive: true,
        }),
    },
  ];

  for (const w of wanted) {
    let existing = session.find(w.find);
    // An object left by an older prep may lack attributes added since; those are
    // fixed at creation time only, so replace it rather than reuse it.
    if (existing.length > 0 && w.needs) {
      let ok = false;
      try {
        ok = w.needs(existing.items(0));
      } catch (_) {}
      if (!ok) {
        session.destroy(existing.items(0));
        console.log(`replaced: ${w.label} (missing required attribute)`);
        existing = session.find(w.find);
      }
    }
    let obj;
    if (existing.length > 0) {
      obj = existing.items(0);
      console.log(`exists : ${w.label} (${existing.length})`);
    } else {
      obj = w.create();
      console.log(`created: ${w.label}`);
    }
    // DisplayAttributes.java needs a raw object handle on its command line.
    const h = obj.handle;
    const num = Buffer.isBuffer(h)
      ? h.length === 4
        ? h.readUInt32LE(0)
        : Number(h.readBigUInt64LE(0))
      : Number(h);
    console.log(`handle : ${w.label} = ${num}`);
  }
} catch (err) {
  console.error("prep failed:", err.message || err);
  process.exitCode = 1;
} finally {
  if (session) {
    try {
      session.logout();
    } catch (_) {}
    try {
      session.close();
    } catch (_) {}
  }
  try {
    mod.finalize();
  } catch (_) {}
}
