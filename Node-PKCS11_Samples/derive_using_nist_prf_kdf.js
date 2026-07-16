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
 * - Derive an AES key with Luna CKM_NIST_PRF_KDF (mirrors C CKM_NIST_PRF_KDF_demo).
 * - Exits 2 if the partition policy rejects the mechanism.
 */

"use strict";
const koffi = require("koffi");
const pkcs11 = require("pkcs11js");
const {
  graphene,
  withSession,
  usageAndExit,
  CKM_NIST_PRF_KDF,
  CK_NIST_PRF_KDF_AES_CMAC,
  LUNA_PRF_KDF_ENCODING_SCHEME_1,
  u32,
} = require("./lib/helper");

console.log("\nderive_using_nist_prf_kdf.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node derive_using_nist_prf_kdf.js <slot_label>",
    "",
    "Example:",
    "node derive_using_nist_prf_kdf.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];

// Windows PKCS#11 uses #pragma pack(1) + 32-bit CK_ULONG; Linux uses
// natural alignment + 64-bit CK_ULONG. Match the host ABI accordingly.
const ULONG = process.platform === "win32" ? "uint32" : "ulong";
const defineMechStruct =
  process.platform === "win32" ? koffi.pack.bind(koffi) : koffi.struct.bind(koffi);
const NIST = defineMechStruct("CK_PRF_KDF_PARAMS_Node", {
  prfType: ULONG,
  pLabel: "void *",
  ulLabelLen: ULONG,
  pContext: "void *",
  ulContextLen: ULONG,
  ulCounter: ULONG,
  ulEncodingScheme: ULONG,
});

(async () => {
  await withSession(slotLabel, async (session) => {
    const base = session.generateKey(graphene.KeyGenMechanism.AES, {
      keyType: graphene.KeyType.AES,
      valueLen: 32,
      token: false,
      derive: true,
      sensitive: true,
      extractable: false,
    });
    console.log("Base AES-256 key generated for NIST PRF KDF.");

    const label = Buffer.from("12345678");
    const context = Buffer.from("12345678");
    const paramBuf = Buffer.alloc(koffi.sizeof(NIST));
    koffi.encode(paramBuf, NIST, {
      prfType: CK_NIST_PRF_KDF_AES_CMAC,
      pLabel: label,
      ulLabelLen: label.length,
      pContext: context,
      ulContextLen: context.length,
      ulCounter: 1,
      ulEncodingScheme: LUNA_PRF_KDF_ENCODING_SCHEME_1,
    });

    const yes = Buffer.from([1]);
    const no = Buffer.from([0]);
    try {
      const handle = session.lib.C_DeriveKey(
        session.handle,
        { mechanism: CKM_NIST_PRF_KDF, parameter: paramBuf },
        base.handle,
        [
          { type: pkcs11.CKA_TOKEN, value: no },
          { type: pkcs11.CKA_PRIVATE, value: yes },
          { type: pkcs11.CKA_SENSITIVE, value: yes },
          { type: pkcs11.CKA_ENCRYPT, value: yes },
          { type: pkcs11.CKA_DECRYPT, value: yes },
          { type: pkcs11.CKA_VALUE_LEN, value: u32(32) },
          { type: pkcs11.CKA_CLASS, value: u32(pkcs11.CKO_SECRET_KEY) },
          { type: pkcs11.CKA_KEY_TYPE, value: u32(pkcs11.CKK_AES) },
        ]
      );
      console.log("AES-256 key derived via CKM_NIST_PRF_KDF.");
      console.log("  --> handle :", Buffer.from(handle).toString("hex"));
      console.log();
      session.lib.C_DestroyObject(session.handle, handle);
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      console.log("NIST PRF KDF failed:", msg);
      process.exitCode = 2;
    }
  });
})();
