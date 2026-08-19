#!/usr/bin/env node
/*********************************************************************************
 *                                                                                *
 * Multi-thread SLIP-10 master-key derivation.                                    *
 * Node port of C_Samples/generating_keys/SLIP10_Bulk_Master_demo.c.              *
 *                                                                                *
 * The "luna-samples" project is provided under the MIT license                   *
 * (https://mit-license.org/).                                                    *
 *                                                                                *
 * Copyright © 2025 Thales Group (original samples)                               *
 *                                                                                *
 *********************************************************************************

 * A master is f(seed, curve). There is no path. One seed and one curve produce
 * exactly one master, so bulk masters need one seed each. Multiple paths on the
 * same seed are children — that is slip10_derive.js.
 *
 * Each worker opens its own session, creates (or reuses) one seed, and derives
 * one master. Firmware 7.8.7+.
 */

"use strict";
const {
  Worker,
  isMainThread,
  workerData,
  parentPort,
} = require("worker_threads");
const koffi = require("koffi");
const {
  graphene,
  requireP11Lib,
  findSlotByLabel,
  getPin,
  usageAndExit,
  CK_ULONG_SIZE,
  CKM_BIP32_MASTER_DERIVE,
  CKK_BIP32,
  CKA_BIP32_VERSION_BYTES,
  CKA_ECDSA_PARAMS,
  BIP32_VERSION_MAINNET_PUB,
  BIP32_VERSION_MAINNET_PRIV,
  SECP256K1_EC_PARAMS,
  P256_EC_PARAMS,
  ED25519_EC_PARAMS,
} = require("./lib/helper");

const CKM_GENERIC_SECRET_KEY_GEN = 0x00000350;
const CKA_TOKEN = 0x00000001;
const CKA_PRIVATE = 0x00000002;
const CKA_LABEL = 0x00000003;
const CKA_KEY_TYPE = 0x00000100;
const CKA_SENSITIVE = 0x00000103;
const CKA_DERIVE = 0x0000010c;
const CKA_BIP32_FINGERPRINT = 0x80001105;

const ULONG = process.platform === "win32" ? "uint32" : "ulong";
const defineStruct =
  process.platform === "win32"
    ? koffi.pack.bind(koffi)
    : koffi.struct.bind(koffi);

const CK_ATTRIBUTE = defineStruct("CK_ATTRIBUTE_Slip10Master", {
  type: ULONG,
  pValue: "void *",
  ulValueLen: ULONG,
});

const CK_MECHANISM = defineStruct("CK_MECHANISM_Slip10Master", {
  mechanism: ULONG,
  pParameter: "void *",
  ulParameterLen: ULONG,
});

const MASTER_PARAMS = defineStruct("CK_BIP32_MASTER_DERIVE_PARAMS_Bulk", {
  pPublicKeyTemplate: "void *",
  ulPublicKeyAttributeCount: ULONG,
  pPrivateKeyTemplate: "void *",
  ulPrivateKeyAttributeCount: ULONG,
  hPublicKey: ULONG,
  hPrivateKey: ULONG,
});

const ATTR_SIZE = koffi.sizeof(CK_ATTRIBUTE);
const TRUE = Buffer.from([1]);
const FALSE = Buffer.from([0]);

const CURVES = {
  secp256k1: { ecParams: SECP256K1_EC_PARAMS, label: "secp256k1 (SLIP-10)" },
  p256: { ecParams: P256_EC_PARAMS, label: "NIST P-256 (SLIP-10)" },
  nist256p1: { ecParams: P256_EC_PARAMS, label: "NIST P-256 (SLIP-10)" },
  ed25519: { ecParams: ED25519_EC_PARAMS, label: "Ed25519 (SLIP-10)" },
};

function ckUlong(n) {
  const b = Buffer.alloc(CK_ULONG_SIZE);
  if (CK_ULONG_SIZE === 4) b.writeUInt32LE(n >>> 0, 0);
  else b.writeBigUInt64LE(BigInt(n >>> 0), 0);
  return b;
}

function handleToNumber(h) {
  if (!Buffer.isBuffer(h)) return Number(h);
  return CK_ULONG_SIZE === 4
    ? h.readUInt32LE(0)
    : Number(h.readBigUInt64LE(0));
}

let binding = null;
function getBinding(libPath) {
  if (binding && binding.libPath === libPath) return binding;
  const lib = koffi.load(libPath);
  const C_DeriveKey = lib.func("C_DeriveKey", ULONG, [
    ULONG,
    "void *",
    ULONG,
    "void *",
    ULONG,
    "void *",
  ]);
  const C_GetAttributeValue = lib.func("C_GetAttributeValue", ULONG, [
    ULONG,
    ULONG,
    "void *",
    ULONG,
  ]);
  binding = { libPath, C_DeriveKey, C_GetAttributeValue };
  return binding;
}

function fingerprintText(libPath, sessionHandle, keyHandle) {
  const value = Buffer.alloc(16);
  const tpl = buildTemplate([[CKA_BIP32_FINGERPRINT, value]]);
  const rv = getBinding(libPath).C_GetAttributeValue(
    sessionHandle,
    keyHandle,
    tpl.buf,
    1
  );
  if (rv !== 0) return "";
  const out = koffi.decode(tpl.buf, CK_ATTRIBUTE);
  return value.subarray(0, Number(out.ulValueLen)).toString("hex");
}

function packMechanism(mechType, paramBuf) {
  const out = Buffer.alloc(koffi.sizeof(CK_MECHANISM));
  koffi.encode(out, CK_MECHANISM, {
    mechanism: mechType >>> 0,
    pParameter: paramBuf,
    ulParameterLen: paramBuf.length,
  });
  return out;
}

const CKR_NAMES = {
  0x00000012: "CKR_ATTRIBUTE_TYPE_INVALID",
  0x00000070: "CKR_MECHANISM_INVALID",
};

function ckrText(rv) {
  const hex = "0x" + (rv >>> 0).toString(16).toUpperCase();
  return CKR_NAMES[rv >>> 0] ? `${CKR_NAMES[rv >>> 0]} (${hex})` : hex;
}

function buildTemplate(attrs) {
  const buf = Buffer.alloc(attrs.length * ATTR_SIZE);
  const keepAlive = [buf];
  attrs.forEach(([type, value], i) => {
    keepAlive.push(value);
    koffi.encode(buf, i * ATTR_SIZE, CK_ATTRIBUTE, {
      type,
      pValue: value,
      ulValueLen: value.length,
    });
  });
  return { buf, count: attrs.length, keepAlive };
}

function keyTemplates(curve, publicLabel, privateLabel) {
  const kt = ckUlong(CKK_BIP32);
  const pub = buildTemplate([
    [CKA_TOKEN, FALSE],
    [CKA_KEY_TYPE, kt],
    [CKA_LABEL, Buffer.from(publicLabel)],
    [CKA_PRIVATE, TRUE],
    [CKA_DERIVE, TRUE],
    [CKA_BIP32_VERSION_BYTES, BIP32_VERSION_MAINNET_PUB],
    [CKA_ECDSA_PARAMS, curve.ecParams],
  ]);
  const priv = buildTemplate([
    [CKA_TOKEN, FALSE],
    [CKA_KEY_TYPE, kt],
    [CKA_LABEL, Buffer.from(privateLabel)],
    [CKA_PRIVATE, TRUE],
    [CKA_SENSITIVE, TRUE],
    [CKA_DERIVE, TRUE],
    [CKA_BIP32_VERSION_BYTES, BIP32_VERSION_MAINNET_PRIV],
    [CKA_ECDSA_PARAMS, curve.ecParams],
  ]);
  return { pub, priv };
}

function safeInitialize(mod) {
  try {
    mod.initialize();
  } catch (err) {
    const msg = err && err.message ? err.message : String(err);
    if (!/ALREADY_INITIALIZED|already initialized/i.test(msg)) throw err;
  }
}

function obtainSeed(session, seedLabel) {
  if (seedLabel) {
    const existing = session.find({
      class: graphene.ObjectClass.SECRET_KEY,
      token: true,
      label: seedLabel,
    });
    if (existing.length > 0) {
      return { seed: existing.items(0), reused: true, seedLabel };
    }
  }

  const template = {
    class: graphene.ObjectClass.SECRET_KEY,
    keyType: graphene.KeyType.GENERIC_SECRET,
    valueLen: 32,
    token: Boolean(seedLabel),
    private: true,
    sensitive: true,
    extractable: false,
    derive: true,
  };
  if (seedLabel) template.label = seedLabel;

  return {
    seed: session.generateKey({ name: CKM_GENERIC_SECRET_KEY_GEN }, template),
    reused: false,
    seedLabel,
  };
}

function deriveMaster(libPath, sessionHandle, curve, seedHandle, index) {
  const { pub, priv } = keyTemplates(
    curve,
    `SLIP10-master-${index}-public`,
    `SLIP10-master-${index}-private`
  );
  const paramBuf = Buffer.alloc(koffi.sizeof(MASTER_PARAMS));
  koffi.encode(paramBuf, MASTER_PARAMS, {
    pPublicKeyTemplate: pub.buf,
    ulPublicKeyAttributeCount: pub.count,
    pPrivateKeyTemplate: priv.buf,
    ulPrivateKeyAttributeCount: priv.count,
    hPublicKey: 0,
    hPrivateKey: 0,
  });

  const rv = getBinding(libPath).C_DeriveKey(
    sessionHandle,
    packMechanism(CKM_BIP32_MASTER_DERIVE, paramBuf),
    seedHandle,
    null,
    0,
    null
  );
  void pub.keepAlive;
  void priv.keepAlive;
  if (rv !== 0) throw new Error("C_DeriveKey MASTER failed with " + ckrText(rv));

  const out = koffi.decode(paramBuf, MASTER_PARAMS);
  return { publicKey: out.hPublicKey, privateKey: out.hPrivateKey };
}

if (!isMainThread) {
  (() => {
    const { p11Lib, slotLabel, curveName, index, seedPrefix } = workerData;
    const curve = CURVES[curveName];
    const mod = graphene.Module.load(p11Lib, "Luna");
    safeInitialize(mod);
    const slot = findSlotByLabel(mod, slotLabel);
    if (!slot) throw new Error("slot not found: " + slotLabel);
    const session = slot.open(
      graphene.SessionFlag.RW_SESSION | graphene.SessionFlag.SERIAL_SESSION
    );
    try {
      const seedLabel = seedPrefix ? `${seedPrefix}-${index}` : undefined;
      const { seed, reused } = obtainSeed(session, seedLabel);
      const master = deriveMaster(
        p11Lib,
        handleToNumber(session.handle),
        curve,
        handleToNumber(seed.handle),
        index
      );
      const fingerprint = fingerprintText(
        p11Lib,
        handleToNumber(session.handle),
        master.publicKey
      );
      parentPort.postMessage({
        ok: true,
        index,
        fingerprint,
        reused,
        seedLabel,
        ...master,
      });
    } finally {
      session.close();
    }
  })();
} else {
  console.log("\nslip10_bulk_master.js\n");

  const args = process.argv.slice(2);
  if (args.length < 3 || args.length > 4) {
    usageAndExit([
      "Usage:",
      "node slip10_bulk_master.js <slot_label> <curve> <num_masters> [seed_label_prefix]",
      "",
      "curve       : secp256k1 | p256 | ed25519",
      "num_masters : one seed and one master per worker thread",
      "prefix      : optional. Seeds persist as <prefix>-0, <prefix>-1, ...",
      "",
      "A master is f(seed, curve). There is no path. Bulk masters need one seed each.",
      "",
      "Example:",
      "node slip10_bulk_master.js myPartition secp256k1 4",
      "node slip10_bulk_master.js myPartition secp256k1 4 wallet\n",
    ]);
  }

  const [slotLabel, curveName, masterArg, seedPrefix] = args;
  const curve = CURVES[curveName];
  if (!curve) {
    console.error(
      `Unknown curve '${curveName}'. Use secp256k1, p256, or ed25519.\n`
    );
    process.exit(1);
  }
  const nMasters = parseInt(masterArg, 10);
  if (!(nMasters > 0)) {
    console.error("num_masters must be a positive integer.\n");
    process.exit(1);
  }

  (async () => {
    const p11Lib = requireP11Lib();
    const pin = await getPin();
    const mod = graphene.Module.load(p11Lib, "Luna");
    mod.initialize();
    let session;
    try {
      console.log("PKCS11 library found at : ", p11Lib);
      const slot = findSlotByLabel(mod, slotLabel);
      if (!slot) {
        console.log("Incorrect token label.\n");
        process.exitCode = 1;
        return;
      }
      console.log("Token found : ", slotLabel);
      session = slot.open(
        graphene.SessionFlag.RW_SESSION | graphene.SessionFlag.SERIAL_SESSION
      );
      session.login(pin, graphene.UserType.USER);
      console.log("Login success.");
      console.log(
        `\nDeriving ${nMasters} master keypairs on ${curve.label}, one seed per worker.\n`
      );

      const results = await Promise.all(
        Array.from({ length: nMasters }, (_, i) => {
          return new Promise((resolve) => {
            let settled = false;
            const done = (msg) => {
              if (settled) return;
              settled = true;
              resolve(msg);
            };
            const w = new Worker(__filename, {
              workerData: {
                p11Lib,
                slotLabel,
                curveName,
                index: i,
                seedPrefix,
              },
            });
            w.on("message", done);
            w.on("error", (err) =>
              done({ ok: false, index: i, error: err.message })
            );
            w.on("exit", (code) => {
              if (code !== 0)
                done({ ok: false, index: i, error: "worker exit " + code });
            });
          });
        })
      );

      let failed = 0;
      for (const r of results) {
        if (r.ok) {
          const seedBit = r.seedLabel
            ? `${r.reused ? "reused" : "stored"} seed "${r.seedLabel}". `
            : "";
          console.log(
            `  --> Master[${r.index}] ${seedBit}fingerprint=${r.fingerprint} priv=${r.privateKey} pub=${r.publicKey}`
          );
        } else {
          failed++;
          console.log(`  --> Master[${r.index}] FAILED: ${r.error}`);
        }
      }

      console.log(
        `\n> ${nMasters - failed} of ${nMasters} master keypairs derived.`
      );
      if (seedPrefix) {
        console.log(
          `> Seeds "${seedPrefix}-0" .. "${seedPrefix}-${nMasters - 1}" stay on the token.`
        );
      }
      console.log("");
      process.exitCode = failed ? 1 : 0;
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      if (
        /CKR_MECHANISM_INVALID|CKR_FUNCTION_NOT_SUPPORTED|CKR_ATTRIBUTE_TYPE_INVALID/i.test(
          msg
        )
      ) {
        console.log(
          `\nSlot "${slotLabel}" rejected the BIP32/SLIP-10 request. SLIP-10 needs firmware 7.8.7 or newer.`
        );
        console.log("Detail:", msg, "\n");
        process.exitCode = 2;
      } else {
        console.error(err);
        process.exitCode = 1;
      }
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
  })();
}
