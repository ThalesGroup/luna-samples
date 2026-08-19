#!/usr/bin/env node
/*********************************************************************************
 *                                                                                *
 * Multi-thread SLIP-10 child-key derivation.                                   *
 * Node port of C_Samples/generating_keys/SLIP10_Derive_demo.c.                   *
 *                                                                                *
 * The "luna-samples" project is provided under the MIT license                   *
 * (https://mit-license.org/).                                                    *
 *                                                                                *
 * Copyright © 2025 Thales Group (original samples)                               *
 *                                                                                *
 *********************************************************************************

 * WHY THE API NAMES SAY BIP32:
 * Luna has no CKM_SLIP10_*. SLIP-10 is selected by calling the BIP32 mechanisms
 * WITH CKA_ECDSA_PARAMS set to a SLIP-10 curve. Omit that attribute and the
 * firmware does classic BIP-32 secp256k1 only.
 *
 * This sample ALWAYS sets CKA_ECDSA_PARAMS → true SLIP-10 (firmware 7.8.7+).
 *
 * OBJECTIVE:
 * - Seed → SLIP-10 master → N workers each derive a distinct child leaf.
 * - Curves: secp256k1, NIST P-256, Ed25519.
 * - Ed25519: hardened-only path (SLIP-10).
 * - Keys are session objects unless a seed label is given, in which case only the
 *   seed is kept on the token so a later run rebuilds the identical tree.
 *
 * WHY koffi:
 * graphene-pk11 cannot marshal CK_BIP32_*_DERIVE_PARAMS — they carry pointers to
 * attribute templates and return the derived handles inside the struct rather
 * than through phKey. koffi builds those structs so C_DeriveKey can be called
 * through pkcs11js directly.
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
  CKM_BIP32_CHILD_DERIVE,
  CKK_BIP32,
  CKA_BIP32_VERSION_BYTES,
  CKA_ECDSA_PARAMS,
  CKF_BIP32_HARDENED,
  CKG_BIP44_PURPOSE,
  CKG_BIP44_COIN_TYPE_BTC,
  CKG_BIP32_EXTERNAL_CHAIN,
  BIP32_VERSION_MAINNET_PUB,
  BIP32_VERSION_MAINNET_PRIV,
  SECP256K1_EC_PARAMS,
  P256_EC_PARAMS,
  ED25519_EC_PARAMS,
} = require("./lib/helper");

const CKM_GENERIC_SECRET_KEY_GEN = 0x00000350;

// Attribute types used in the BIP32 templates.
const CKA_TOKEN = 0x00000001;
const CKA_PRIVATE = 0x00000002;
const CKA_LABEL = 0x00000003;
const CKA_KEY_TYPE = 0x00000100;
const CKA_SENSITIVE = 0x00000103;
const CKA_DERIVE = 0x0000010c;
const CKA_VERIFY = 0x0000010a;
const CKA_SIGN = 0x00000108;
const CKA_BIP32_FINGERPRINT = 0x80001105;
const CKA_BIP32_PARENT_FINGERPRINT = 0x80001106;
const CKA_BIP32_CHILD_DEPTH = 0x80001103;

// Luna cryptoki packs structs to 1 byte with a 32-bit CK_ULONG on Windows, and
// uses natural alignment with a 64-bit CK_ULONG elsewhere.
const ULONG = process.platform === "win32" ? "uint32" : "ulong";
const defineStruct =
  process.platform === "win32"
    ? koffi.pack.bind(koffi)
    : koffi.struct.bind(koffi);

const CK_ATTRIBUTE = defineStruct("CK_ATTRIBUTE_Slip10", {
  type: ULONG,
  pValue: "void *",
  ulValueLen: ULONG,
});

const CK_MECHANISM = defineStruct("CK_MECHANISM_Slip10", {
  mechanism: ULONG,
  pParameter: "void *",
  ulParameterLen: ULONG,
});

const MASTER_PARAMS = defineStruct("CK_BIP32_MASTER_DERIVE_PARAMS_Node", {
  pPublicKeyTemplate: "void *",
  ulPublicKeyAttributeCount: ULONG,
  pPrivateKeyTemplate: "void *",
  ulPrivateKeyAttributeCount: ULONG,
  hPublicKey: ULONG,
  hPrivateKey: ULONG,
});

const CHILD_PARAMS = defineStruct("CK_BIP32_CHILD_DERIVE_PARAMS_Node", {
  pPublicKeyTemplate: "void *",
  ulPublicKeyAttributeCount: ULONG,
  pPrivateKeyTemplate: "void *",
  ulPrivateKeyAttributeCount: ULONG,
  pulPath: "void *",
  ulPathLen: ULONG,
  hPublicKey: ULONG,
  hPrivateKey: ULONG,
  ulPathErrorIndex: ULONG,
});

const ATTR_SIZE = koffi.sizeof(CK_ATTRIBUTE);
const TRUE = Buffer.from([1]);
const FALSE = Buffer.from([0]);

const CURVES = {
  secp256k1: {
    ecParams: SECP256K1_EC_PARAMS,
    hardenedOnly: false,
    label: "secp256k1 (SLIP-10)",
  },
  p256: {
    ecParams: P256_EC_PARAMS,
    hardenedOnly: false,
    label: "NIST P-256 (SLIP-10)",
  },
  nist256p1: {
    ecParams: P256_EC_PARAMS,
    hardenedOnly: false,
    label: "NIST P-256 (SLIP-10)",
  },
  ed25519: {
    ecParams: ED25519_EC_PARAMS,
    hardenedOnly: true,
    label: "Ed25519 (SLIP-10, hardened-only)",
  },
};

/** CK_ULONG buffer matching the host ABI. */
function ckUlong(n) {
  const b = Buffer.alloc(CK_ULONG_SIZE);
  if (CK_ULONG_SIZE === 4) b.writeUInt32LE(n >>> 0, 0);
  else b.writeBigUInt64LE(BigInt(n >>> 0), 0);
  return b;
}

/** graphene/pkcs11js hand back handles as little-endian buffers. */
function handleToNumber(h) {
  if (!Buffer.isBuffer(h)) return Number(h);
  return CK_ULONG_SIZE === 4
    ? h.readUInt32LE(0)
    : Number(h.readBigUInt64LE(0));
}

/**
 * pkcs11js cannot issue this call: Luna returns both derived handles inside the
 * mechanism parameter and requires phKey to be NULL, while pkcs11js always
 * passes a real phKey and gets CKR_ARGUMENTS_BAD back. Bind C_DeriveKey directly.
 */
let binding = null;
function getBinding(libPath) {
  if (binding && binding.libPath === libPath) return binding;
  const lib = koffi.load(libPath);
  const C_DeriveKey = lib.func("C_DeriveKey", ULONG, [
    ULONG, // hSession
    "void *", // pMechanism
    ULONG, // hBaseKey
    "void *", // pTemplate
    ULONG, // ulAttributeCount
    "void *", // phKey
  ]);
  // Bound alongside C_DeriveKey so a derived handle's vendor BIP32 attributes can be
  // read without handing the handle back to graphene.
  const C_GetAttributeValue = lib.func("C_GetAttributeValue", ULONG, [
    ULONG, // hSession
    ULONG, // hObject
    "void *", // pTemplate
    ULONG, // ulCount
  ]);
  binding = { libPath, C_DeriveKey, C_GetAttributeValue };
  return binding;
}

function getDeriveKey(libPath) {
  return getBinding(libPath).C_DeriveKey;
}

/**
 * CKA_BIP32_FINGERPRINT, the short identifier SLIP-10 computes from a key's public value.
 * Object handles change on every run; a fingerprint depends only on the seed and the path,
 * so it is what shows that two runs rebuilt the same tree.
 */
function attrHex(libPath, sessionHandle, keyHandle, type) {
  const value = Buffer.alloc(16);
  const tpl = buildTemplate([[type, value]]);
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

function fingerprintText(libPath, sessionHandle, keyHandle) {
  return attrHex(libPath, sessionHandle, keyHandle, CKA_BIP32_FINGERPRINT);
}

function parentFingerprintText(libPath, sessionHandle, keyHandle) {
  return attrHex(libPath, sessionHandle, keyHandle, CKA_BIP32_PARENT_FINGERPRINT);
}

function childDepth(libPath, sessionHandle, keyHandle) {
  const value = Buffer.alloc(CK_ULONG_SIZE);
  const tpl = buildTemplate([[CKA_BIP32_CHILD_DEPTH, value]]);
  const rv = getBinding(libPath).C_GetAttributeValue(
    sessionHandle,
    keyHandle,
    tpl.buf,
    1
  );
  if (rv !== 0) return -1;
  return CK_ULONG_SIZE === 4 ? value.readUInt32LE(0) : Number(value.readBigUInt64LE(0));
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
  0x00000007: "CKR_ARGUMENTS_BAD",
  0x00000012: "CKR_ATTRIBUTE_TYPE_INVALID",
  0x00000013: "CKR_ATTRIBUTE_VALUE_INVALID",
  0x00000070: "CKR_MECHANISM_INVALID",
  0x00000071: "CKR_MECHANISM_PARAM_INVALID",
  0x00000068: "CKR_KEY_HANDLE_INVALID",
  0x80000083: "CKR_BIP32_CHILD_INDEX_INVALID",
  0x80000084: "CKR_BIP32_INVALID_HARDENED_DERIVATION",
  0x80000085: "CKR_BIP32_MASTER_SEED_LEN_INVALID",
  0x80000086: "CKR_BIP32_MASTER_SEED_INVALID",
  0x80000087: "CKR_BIP32_INVALID_KEY_PATH_LEN",
};

function ckrText(rv) {
  const hex = "0x" + (rv >>> 0).toString(16).toUpperCase();
  return CKR_NAMES[rv >>> 0] ? `${CKR_NAMES[rv >>> 0]} (${hex})` : hex;
}

/**
 * Pack [type, valueBuffer] pairs into a CK_ATTRIBUTE array.
 * The returned `keepAlive` must stay reachable until C_DeriveKey returns,
 * otherwise the value buffers can be collected while the HSM still holds
 * pointers to them.
 */
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

function keyTemplates(curve, publicLabel, privateLabel, isMaster) {
  const kt = ckUlong(CKK_BIP32);
  const pub = buildTemplate([
    [CKA_TOKEN, FALSE],
    [CKA_KEY_TYPE, kt],
    [CKA_LABEL, Buffer.from(publicLabel)],
    [CKA_PRIVATE, TRUE],
    [isMaster ? CKA_DERIVE : CKA_VERIFY, TRUE],
    [CKA_BIP32_VERSION_BYTES, BIP32_VERSION_MAINNET_PUB],
    [CKA_ECDSA_PARAMS, curve.ecParams],
  ]);
  const priv = buildTemplate([
    [CKA_TOKEN, FALSE],
    [CKA_KEY_TYPE, kt],
    [CKA_LABEL, Buffer.from(privateLabel)],
    [CKA_PRIVATE, TRUE],
    [CKA_SENSITIVE, TRUE],
    [isMaster ? CKA_DERIVE : CKA_SIGN, TRUE],
    [CKA_BIP32_VERSION_BYTES, BIP32_VERSION_MAINNET_PRIV],
    [CKA_ECDSA_PARAMS, curve.ecParams],
  ]);
  return { pub, priv };
}

/** BIP-44 leaf m/44'/0'/0'/change/address; Ed25519 hardens every level. */
function buildPath(curve, index) {
  const H = CKF_BIP32_HARDENED;
  const levels = [
    H | CKG_BIP44_PURPOSE,
    H | CKG_BIP44_COIN_TYPE_BTC,
    H | 0,
    curve.hardenedOnly ? H | CKG_BIP32_EXTERNAL_CHAIN : CKG_BIP32_EXTERNAL_CHAIN,
    curve.hardenedOnly ? H | index : index,
  ];
  const buf = Buffer.alloc(levels.length * CK_ULONG_SIZE);
  levels.forEach((v, i) => {
    if (CK_ULONG_SIZE === 4) buf.writeUInt32LE(v >>> 0, i * 4);
    else buf.writeBigUInt64LE(BigInt(v >>> 0), i * 8);
  });
  return { buf, length: levels.length };
}

function safeInitialize(mod) {
  try {
    mod.initialize();
  } catch (err) {
    const msg = err && err.message ? err.message : String(err);
    if (!/ALREADY_INITIALIZED|already initialized/i.test(msg)) throw err;
  }
}

/**
 * Obtains the 32 byte generic secret that seeds the tree.
 * Without a seed label it is a session object, so every run builds a different tree.
 * With one it is kept on the token and reused, which is how a deployment works: the seed
 * is the only thing worth storing and everything below it is recomputed on demand.
 * It is marked non-extractable, so the only way it leaves the HSM is a backup or a clone.
 */
function obtainSeed(session, seedLabel) {
  if (seedLabel) {
    const existing = session.find({
      class: graphene.ObjectClass.SECRET_KEY,
      token: true,
      label: seedLabel,
    });
    if (existing.length > 0) {
      console.log(`Seed "${seedLabel}" found on the token.`);
      return existing.items(0);
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

  const seed = session.generateKey(
    { name: CKM_GENERIC_SECRET_KEY_GEN },
    template
  );
  console.log(
    seedLabel
      ? `Seed generated and stored as "${seedLabel}".`
      : "Seed key generated."
  );
  return seed;
}

function deriveMaster(libPath, sessionHandle, curve, seedHandle) {
  const { pub, priv } = keyTemplates(
    curve,
    "SLIP10-master-public",
    "SLIP10-master-private",
    true
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

  const rv = getDeriveKey(libPath)(
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

function deriveChild(libPath, sessionHandle, curve, masterPrivate, index) {
  const { pub, priv } = keyTemplates(
    curve,
    `SLIP10-child-${index}-pub`,
    `SLIP10-child-${index}-pri`,
    false
  );
  const path = buildPath(curve, index);
  const paramBuf = Buffer.alloc(koffi.sizeof(CHILD_PARAMS));
  koffi.encode(paramBuf, CHILD_PARAMS, {
    pPublicKeyTemplate: pub.buf,
    ulPublicKeyAttributeCount: pub.count,
    pPrivateKeyTemplate: priv.buf,
    ulPrivateKeyAttributeCount: priv.count,
    pulPath: path.buf,
    ulPathLen: path.length,
    hPublicKey: 0,
    hPrivateKey: 0,
    ulPathErrorIndex: 0,
  });

  const rv = getDeriveKey(libPath)(
    sessionHandle,
    packMechanism(CKM_BIP32_CHILD_DERIVE, paramBuf),
    masterPrivate,
    null,
    0,
    null
  );
  void pub.keepAlive;
  void priv.keepAlive;
  void path.buf;

  const out = koffi.decode(paramBuf, CHILD_PARAMS);
  if (rv !== 0) {
    throw new Error(
      `C_DeriveKey CHILD failed with ${ckrText(rv)} (path error index ${out.ulPathErrorIndex})`
    );
  }
  return { publicKey: out.hPublicKey, privateKey: out.hPrivateKey };
}

if (!isMainThread) {
  (() => {
    const { p11Lib, slotLabel, curveName, masterPrivate, index } = workerData;
    const curve = CURVES[curveName];
    const mod = graphene.Module.load(p11Lib, "Luna");
    safeInitialize(mod);
    const slot = findSlotByLabel(mod, slotLabel);
    if (!slot) throw new Error("slot not found: " + slotLabel);
    const session = slot.open(
      graphene.SessionFlag.RW_SESSION | graphene.SessionFlag.SERIAL_SESSION
    );
    try {
      const child = deriveChild(
        p11Lib,
        handleToNumber(session.handle),
        curve,
        masterPrivate,
        index
      );
      const sessionHandle = handleToNumber(session.handle);
      const fingerprint = fingerprintText(p11Lib, sessionHandle, child.publicKey);
      const parentFp = parentFingerprintText(
        p11Lib,
        sessionHandle,
        child.publicKey
      );
      const depth = childDepth(p11Lib, sessionHandle, child.publicKey);
      parentPort.postMessage({
        ok: true,
        index,
        fingerprint,
        parentFp,
        depth,
        ...child,
      });
    } finally {
      session.close();
    }
  })();
} else {
  console.log("\nslip10_derive.js\n");

  const args = process.argv.slice(2);
  if (args.length < 3 || args.length > 4) {
    usageAndExit([
      "Usage:",
      "node slip10_derive.js <slot_label> <curve> <num_children> [seed_label]",
      "",
      "curve        : secp256k1 | p256 | ed25519",
      "               (CKA_ECDSA_PARAMS is always set = SLIP-10, firmware 7.8.7+)",
      "num_children : one distinct BIP-44 leaf per worker thread",
      "seed_label   : optional. Without it the seed is a session object and every run",
      "               builds a different tree. With it the seed is kept on the token,",
      "               so a later run with the same label rebuilds the identical tree.",
      "",
      "Example:",
      "node slip10_derive.js myPartition ed25519 4",
      "node slip10_derive.js myPartition ed25519 4 my-slip10-seed\n",
    ]);
  }

  const [slotLabel, curveName, childArg, seedLabel] = args;
  const curve = CURVES[curveName];
  if (!curve) {
    console.error(
      `Unknown curve '${curveName}'. Use secp256k1, p256, or ed25519.\n`
    );
    process.exit(1);
  }
  const nChildren = parseInt(childArg, 10);
  if (!(nChildren > 0)) {
    console.error("num_children must be a positive integer.\n");
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

      const seed = obtainSeed(session, seedLabel);

      const master = deriveMaster(
        p11Lib,
        handleToNumber(session.handle),
        curve,
        handleToNumber(seed.handle)
      );
      console.log(`SLIP-10 master keypair derived (${curve.label}).`);
      console.log(
        "  --> fingerprint        :",
        fingerprintText(
          p11Lib,
          handleToNumber(session.handle),
          master.publicKey
        )
      );
      console.log("  --> private key handle :", master.privateKey);
      console.log("  --> public key handle  :", master.publicKey);

      if (!master.privateKey) {
        console.log(
          "\nFirmware did not return a master private key handle; cannot derive children.\n"
        );
        process.exitCode = 2;
        return;
      }

      console.log(
        `\nDeriving ${nChildren} distinct child leaves on ${curve.label}.\n`
      );

      const results = await Promise.all(
        Array.from({ length: nChildren }, (_, i) => {
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
                masterPrivate: master.privateKey,
                index: i,
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
          console.log(
            `  --> Child[${r.index}] derived  depth=${r.depth} fingerprint=${r.fingerprint} parent=${r.parentFp} priv=${r.privateKey} pub=${r.publicKey}`
          );
        } else {
          failed++;
          console.log(`  --> Child[${r.index}] FAILED: ${r.error}`);
        }
      }

      console.log(
        `\n> ${nChildren - failed} of ${nChildren} child keypairs derived.`
      );
      if (seedLabel) {
        console.log(
          `> Seed "${seedLabel}" stays on the token. Run again with the same label to rebuild this tree.`
        );
      }
      console.log("");
      process.exitCode = failed ? 1 : 0;
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      // A partition below firmware 7.8.7 has no SLIP-10 support. It reports that as a bad
      // mechanism or, more often, as a bad attribute type once it meets CKA_ECDSA_PARAMS
      // on a BIP32 template.
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
