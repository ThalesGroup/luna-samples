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
 * - Wrap a secret key using AES key-wrap.
 * - Prefers NIST CKM_AES_KEY_WRAP; falls back to Luna CKM_AES_KW (common on Cloud HSM).
 */

"use strict";
const fs = require("fs");
const {
  graphene,
  withSession,
  usageAndExit,
  findKeyByLabel,
  CKM_AES_KW,
} = require("./lib/helper");

console.log("\nwrap_secret_key_using_aes.js\n");

if (process.argv.length !== 6) {
  usageAndExit([
    "Usage:",
    "node wrap_secret_key_using_aes.js <slot_label> <wrapping_key_label> <key_to_wrap_label> <output_file_name>",
    "",
    "Example:",
    "node wrap_secret_key_using_aes.js myPartition MasterKey DataKey DataKey.dat\n",
  ]);
}

const [slotLabel, wrappingKeyLabel, keyToWrapLabel, outfile] = process.argv.slice(2);

function wrapWithFallback(session, wrappingKey, keyToWrap) {
  try {
    const wrapped = session.wrapKey(
      graphene.MechanismEnum.AES_KEY_WRAP,
      wrappingKey,
      keyToWrap
    );
    return { wrapped, mech: "AES_KEY_WRAP", meta: null };
  } catch (_) {
    const iv = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    const wrapped = session.wrapKey(
      { name: CKM_AES_KW, params: iv },
      wrappingKey,
      keyToWrap
    );
    return { wrapped, mech: "CKM_AES_KW", meta: { iv } };
  }
}

(async () => {
  await withSession(slotLabel, async (session) => {
    const wrappingKey = findKeyByLabel(
      session,
      wrappingKeyLabel,
      graphene.ObjectClass.SECRET_KEY
    );
    console.log("\t> Wrapping key found : ", wrappingKeyLabel);

    const keyToWrap = findKeyByLabel(
      session,
      keyToWrapLabel,
      graphene.ObjectClass.SECRET_KEY
    );
    console.log("\t> Key to wrap found : ", keyToWrapLabel);

    const { wrapped, mech, meta } = wrapWithFallback(
      session,
      wrappingKey,
      keyToWrap
    );
    const payload = meta
      ? Buffer.concat([Buffer.from("KW1\0"), meta.iv, wrapped])
      : wrapped;
    fs.writeFileSync(outfile, payload);
    console.log("Wrapped with", mech, "->", outfile, "\n");
  });
})();
