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
 * - Derive an AES key with CKM_PKCS5_PBKD2 (mirrors C CKM_PKCS5_PBKD2_demo).
 * - Not FIPS-approved; exits 2 if the partition policy rejects the mechanism.
 */

"use strict";
const koffi = require("koffi");
const pkcs11 = require("pkcs11js");
const {
  withSession,
  usageAndExit,
  CKM_PKCS5_PBKD2,
  u32,
} = require("./lib/helper");

console.log("\nderive_using_pbkd2.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node derive_using_pbkd2.js <slot_label>",
    "",
    "Example:",
    "node derive_using_pbkd2.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];

// PKCS#11 mandates 1-byte struct packing on Windows (#pragma pack(1)),
// so use koffi.pack — koffi.struct's natural alignment breaks the ABI.
const PBKD2 = koffi.pack("CK_PKCS5_PBKD2_PARAMS2_Node", {
  saltSource: "uint32",
  pSaltSourceData: "void *",
  ulSaltSourceDataLen: "uint32",
  iterations: "uint32",
  prf: "uint32",
  pPrfData: "void *",
  ulPrfDataLen: "uint32",
  pPassword: "void *",
  ulPasswordLen: "uint32",
});

(async () => {
  await withSession(slotLabel, async (session) => {
    const salt = Buffer.from("HelloHolaNamasteySalamKonichiwaNihao");
    const password = Buffer.from("Th3W0rld$M0$+$3cur3P@$$w0rd");
    const paramBuf = Buffer.alloc(koffi.sizeof(PBKD2));
    koffi.encode(paramBuf, PBKD2, {
      saltSource: 1, // CKZ_SALT_SPECIFIED
      pSaltSourceData: salt,
      ulSaltSourceDataLen: salt.length,
      iterations: 1000,
      prf: 1, // CKP_PKCS5_PBKD2_HMAC_SHA1
      pPrfData: null,
      ulPrfDataLen: 0,
      pPassword: password,
      ulPasswordLen: password.length,
    });
    const yes = Buffer.from([1]);
    const no = Buffer.from([0]);
    try {
      const handle = session.lib.C_GenerateKey(
        session.handle,
        { mechanism: CKM_PKCS5_PBKD2, parameter: paramBuf },
        [
          { type: pkcs11.CKA_TOKEN, value: no },
          { type: pkcs11.CKA_PRIVATE, value: yes },
          { type: pkcs11.CKA_ENCRYPT, value: yes },
          { type: pkcs11.CKA_DECRYPT, value: yes },
          { type: pkcs11.CKA_SENSITIVE, value: yes },
          { type: pkcs11.CKA_EXTRACTABLE, value: no },
          { type: pkcs11.CKA_VALUE_LEN, value: u32(32) },
          { type: pkcs11.CKA_CLASS, value: u32(pkcs11.CKO_SECRET_KEY) },
          { type: pkcs11.CKA_KEY_TYPE, value: u32(pkcs11.CKK_AES) },
        ]
      );
      console.log("AES-256 key derived via CKM_PKCS5_PBKD2.");
      console.log("  --> handle :", Buffer.from(handle).toString("hex"));
      console.log();
      session.lib.C_DestroyObject(session.handle, handle);
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      console.log("PBKD2 failed:", msg);
      console.log("Note: CKM_PKCS5_PBKD2 is disallowed on FIPS-restricted partitions.\n");
      process.exitCode = 2;
    }
  });
})();
