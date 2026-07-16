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
 * - Set CKA_USAGE_LIMIT on an AES key and encrypt until the HSM rejects further use
 *   (mirrors C Usage_Limit_demo).
 */

"use strict";
const pkcs11 = require("pkcs11js");
const {
  graphene,
  withSession,
  usageAndExit,
  CKA_USAGE_LIMIT,
  u32,
} = require("./lib/helper");

console.log("\nusage_limit_demo.js\n");
if (process.argv.length !== 4) {
  usageAndExit([
    "Usage:",
    "node usage_limit_demo.js <slot_label> <usage_limit>",
    "",
    "Example:",
    "node usage_limit_demo.js myPartition 3\n",
  ]);
}
const slotLabel = process.argv[2];
const usageLimit = parseInt(process.argv[3], 10);
if (!(usageLimit > 0)) {
  console.error("usage_limit must be a positive integer.\n");
  process.exit(1);
}

(async () => {
  await withSession(slotLabel, async (session) => {
    const yes = Buffer.from([1]);
    const no = Buffer.from([0]);
    const handle = session.lib.C_GenerateKey(
      session.handle,
      { mechanism: pkcs11.CKM_AES_KEY_GEN, parameter: null },
      [
        { type: pkcs11.CKA_TOKEN, value: no },
        { type: pkcs11.CKA_PRIVATE, value: yes },
        { type: pkcs11.CKA_ENCRYPT, value: yes },
        { type: pkcs11.CKA_DECRYPT, value: yes },
        { type: pkcs11.CKA_WRAP, value: no },
        { type: pkcs11.CKA_UNWRAP, value: no },
        { type: pkcs11.CKA_SENSITIVE, value: yes },
        { type: pkcs11.CKA_EXTRACTABLE, value: no },
        { type: pkcs11.CKA_MODIFIABLE, value: no },
        { type: CKA_USAGE_LIMIT, value: u32(usageLimit) },
        { type: pkcs11.CKA_VALUE_LEN, value: u32(32) },
      ]
    );
    console.log(
      "AES-256 key generated with CKA_USAGE_LIMIT =",
      usageLimit
    );

    const iv = Buffer.from("1234567812345678");
    const data = Buffer.from(
      "Earth is the third planet of our Solar System."
    );
    let ops = 0;
    for (;;) {
      try {
        session.lib.C_EncryptInit(
          session.handle,
          { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter: iv },
          handle
        );
        session.lib.C_Encrypt(session.handle, data, Buffer.alloc(128));
        ops++;
        console.log("  --> encrypt ok, operation #", ops);
      } catch (err) {
        const msg = err && err.message ? err.message : String(err);
        console.log(
          "\n> Usage limit reached after",
          ops,
          "encrypt(s). Last error:",
          msg
        );
        console.log(
          "  (C sample reports CKR_KEY_NOT_ACTIVE; some images return a vendor code.)\n"
        );
        break;
      }
      if (ops > usageLimit + 2) {
        console.log("Unexpected: exceeded limit without error.\n");
        process.exitCode = 1;
        break;
      }
    }
    try {
      session.lib.C_DestroyObject(session.handle, handle);
    } catch (_) {
      /* ignore */
    }
  });
})();
