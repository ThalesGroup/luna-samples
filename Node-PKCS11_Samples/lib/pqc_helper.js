"use strict";

/**
 * Shared helpers for Node PQC samples (raw pkcs11js + koffi for Luna CA_ encaps).
 * graphine-pk11 does not model PKCS#11 3.2 PQC templates/params.
 *
 * Requires Luna Client 10.9+ and firmware with the relevant mechanisms
 * (ML-DSA/ML-KEM: 7.9+, HSS: 7.8.9+). Probe with pqc_mechanism_probe.js.
 */

const pkcs11js = require("pkcs11js");
const koffi = require("koffi");
const {
  requireP11Lib,
  getPin,
  usageAndExit,
  CK_ULONG_SIZE,
  ulong,
  CKM_AES_KWP,
} = require("./helper");

// --- PKCS#11 3.2 / Luna PQC constants (not in current pkcs11js) ---
const CKM_ML_KEM_KEY_PAIR_GEN = 0x0000000f;
const CKM_ML_KEM = 0x00000017;
const CKM_ML_DSA_KEY_PAIR_GEN = 0x0000001c;
const CKM_ML_DSA = 0x0000001d;
const CKM_HASH_ML_DSA = 0x0000001f;
const CKM_HASH_ML_DSA_SHA3_512 = 0x0000002a;
const CKM_HSS_KEY_PAIR_GEN = 0x00004032;
const CKM_HSS = 0x00004033;
const CKM_EXTMU_ML_DSA = 0x80000175;
const CKM_SHA256 = 0x00000250;
const CKM_SHA3_512 = 0x000002b3;

const CKK_HSS = 0x00000046;
const CKK_ML_KEM = 0x00000049;
const CKK_ML_DSA = 0x0000004a;

const CKA_HSS_LEVELS = 0x00000617;
const CKA_HSS_LMS_TYPES = 0x0000061a;
const CKA_HSS_LMOTS_TYPES = 0x0000061b;
const CKA_HSS_KEYS_REMAINING = 0x0000061c;
const CKA_PARAMETER_SET = 0x0000061d;
const CKA_ENCAPSULATE = 0x00000633;
const CKA_DECAPSULATE = 0x00000634;

const CKP_ML_DSA_44 = 1;
const CKP_ML_DSA_65 = 2;
const CKP_ML_DSA_87 = 3;
const CKP_ML_KEM_512 = 1;
const CKP_ML_KEM_768 = 2;
const CKP_ML_KEM_1024 = 3;

const CKH_HEDGE_PREFERRED = 0;
const CKH_HEDGE_REQUIRED = 1;
const CKH_DETERMINISTIC_REQUIRED = 2;

const LMS_SHA256_M32_H5 = 0x00000005;
const LMOTS_SHA256_N32_W8 = 0x00000004;

const ML_DSA_SETS = { "44": CKP_ML_DSA_44, "65": CKP_ML_DSA_65, "87": CKP_ML_DSA_87 };
const ML_KEM_SETS = {
  "512": CKP_ML_KEM_512,
  "768": CKP_ML_KEM_768,
  "1024": CKP_ML_KEM_1024,
};
const ML_KEM_CT_LEN = { 1: 768, 2: 1088, 3: 1568 };

/** Luna cryptoki uses #pragma pack(1) on Windows; natural alignment elsewhere. */
const packStruct =
  process.platform === "win32" ? koffi.pack.bind(koffi) : koffi.struct.bind(koffi);

const CK_ULONG_T = CK_ULONG_SIZE === 4 ? "uint32" : "uint64";
const PTR = "void *";

const SignAdditionalContext = packStruct("CK_SIGN_ADDITIONAL_CONTEXT", {
  hedgeVariant: CK_ULONG_T,
  pContext: PTR,
  ulContextLen: CK_ULONG_T,
});

const HashSignAdditionalContext = packStruct("CK_HASH_SIGN_ADDITIONAL_CONTEXT", {
  hedgeVariant: CK_ULONG_T,
  pContext: PTR,
  ulContextLen: CK_ULONG_T,
  hash: CK_ULONG_T,
});

const CkMechanism = packStruct("CK_MECHANISM_PQC", {
  mechanism: CK_ULONG_T,
  pParameter: PTR,
  ulParameterLen: CK_ULONG_T,
});

const CkAttribute = packStruct("CK_ATTRIBUTE_PQC", {
  type: CK_ULONG_T,
  pValue: PTR,
  ulValueLen: CK_ULONG_T,
});

function tokenLabel(pkcs11, slot) {
  const info = pkcs11.C_GetTokenInfo(slot);
  return String(info.label || "").replace(/\0/g, "").trim();
}

function findSlot(pkcs11, label) {
  const slots = pkcs11.C_GetSlotList(true);
  for (const slot of slots) {
    try {
      if (tokenLabel(pkcs11, slot) === label) return slot;
    } catch (_) {}
  }
  return null;
}

function handleToNumber(h) {
  if (Buffer.isBuffer(h)) {
    return CK_ULONG_SIZE === 4 ? h.readUInt32LE(0) : Number(h.readBigUInt64LE(0));
  }
  return Number(h);
}

function ckR(err) {
  if (!err) return "";
  const code = err.code != null ? "0x" + Number(err.code).toString(16) : "";
  return (err.message || String(err)) + (code ? " (" + code + ")" : "");
}

/**
 * Pack CK_SIGN_ADDITIONAL_CONTEXT. Keeps contextBuf alive via returned.refs.
 */
function packSignAdditionalContext(hedgeVariant, contextBuf) {
  const refs = [];
  let pContext = null;
  let ulContextLen = 0;
  if (contextBuf && contextBuf.length) {
    const buf = Buffer.from(contextBuf);
    refs.push(buf);
    pContext = buf;
    ulContextLen = buf.length;
  }
  const out = Buffer.alloc(koffi.sizeof(SignAdditionalContext));
  koffi.encode(out, SignAdditionalContext, {
    hedgeVariant,
    pContext,
    ulContextLen,
  });
  return { buffer: out, refs };
}

function packHashSignAdditionalContext(hedgeVariant, contextBuf, hashMech) {
  const refs = [];
  let pContext = null;
  let ulContextLen = 0;
  if (contextBuf && contextBuf.length) {
    const buf = Buffer.from(contextBuf);
    refs.push(buf);
    pContext = buf;
    ulContextLen = buf.length;
  }
  const out = Buffer.alloc(koffi.sizeof(HashSignAdditionalContext));
  koffi.encode(out, HashSignAdditionalContext, {
    hedgeVariant,
    pContext,
    ulContextLen,
    hash: hashMech >>> 0,
  });
  return { buffer: out, refs };
}

function generateMlDsaKeyPair(pkcs11, session, paramSet, labelBase) {
  const label = labelBase || "node-mldsa-" + Date.now();
  return pkcs11.C_GenerateKeyPair(
    session,
    { mechanism: CKM_ML_DSA_KEY_PAIR_GEN },
    [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
      { type: pkcs11js.CKA_TOKEN, value: false },
      { type: pkcs11js.CKA_PRIVATE, value: false },
      { type: pkcs11js.CKA_VERIFY, value: true },
      { type: pkcs11js.CKA_KEY_TYPE, value: CKK_ML_DSA },
      { type: CKA_PARAMETER_SET, value: paramSet },
      { type: pkcs11js.CKA_LABEL, value: label + "-pub" },
    ],
    [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
      { type: pkcs11js.CKA_TOKEN, value: false },
      { type: pkcs11js.CKA_PRIVATE, value: true },
      { type: pkcs11js.CKA_SENSITIVE, value: true },
      { type: pkcs11js.CKA_EXTRACTABLE, value: false },
      { type: pkcs11js.CKA_SIGN, value: true },
      { type: pkcs11js.CKA_KEY_TYPE, value: CKK_ML_DSA },
      { type: pkcs11js.CKA_LABEL, value: label + "-priv" },
    ]
  );
}

function generateMlKemKeyPair(pkcs11, session, paramSet, labelBase) {
  const label = labelBase || "node-mlkem-" + Date.now();
  return pkcs11.C_GenerateKeyPair(
    session,
    { mechanism: CKM_ML_KEM_KEY_PAIR_GEN },
    [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
      { type: pkcs11js.CKA_TOKEN, value: false },
      { type: pkcs11js.CKA_PRIVATE, value: false },
      { type: pkcs11js.CKA_KEY_TYPE, value: CKK_ML_KEM },
      { type: CKA_PARAMETER_SET, value: paramSet },
      { type: CKA_ENCAPSULATE, value: true },
      { type: pkcs11js.CKA_LABEL, value: label + "-pub" },
    ],
    [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
      { type: pkcs11js.CKA_TOKEN, value: false },
      { type: pkcs11js.CKA_PRIVATE, value: true },
      { type: pkcs11js.CKA_SENSITIVE, value: true },
      { type: pkcs11js.CKA_EXTRACTABLE, value: false },
      { type: pkcs11js.CKA_KEY_TYPE, value: CKK_ML_KEM },
      { type: CKA_PARAMETER_SET, value: paramSet },
      { type: CKA_DECAPSULATE, value: true },
      { type: pkcs11js.CKA_LABEL, value: label + "-priv" },
    ]
  );
}

function destroyPair(pkcs11, session, keys) {
  if (!keys) return;
  try {
    if (keys.privateKey) pkcs11.C_DestroyObject(session, keys.privateKey);
  } catch (_) {}
  try {
    if (keys.publicKey) pkcs11.C_DestroyObject(session, keys.publicKey);
  } catch (_) {}
}

/**
 * Open RW session on slot label, login as CO, run fn(ctx), cleanup.
 * ctx: { pkcs11, session, slot, libPath }
 */
async function withPqcSession(slotLabel, fn) {
  const pin = await getPin();
  const libPath = requireP11Lib();
  const pkcs11 = new pkcs11js.PKCS11();
  pkcs11.load(libPath);
  pkcs11.C_Initialize();
  let session = null;
  try {
    const slot = findSlot(pkcs11, slotLabel);
    if (!slot) throw new Error("Incorrect token label: " + slotLabel);
    session = pkcs11.C_OpenSession(
      slot,
      pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION
    );
    pkcs11.C_Login(session, pkcs11js.CKU_USER, pin);
    return await fn({ pkcs11, session, slot, libPath });
  } finally {
    try {
      if (session) {
        try {
          pkcs11.C_Logout(session);
        } catch (_) {}
        pkcs11.C_CloseSession(session);
      }
    } catch (_) {}
    try {
      pkcs11.C_Finalize();
    } catch (_) {}
  }
}

/** Lazy-loaded koffi bindings for Luna CA_EncapsulateKey / CA_DecapsulateKey. */
let caBindings = null;

function getCaBindings(libPath) {
  if (caBindings && caBindings.libPath === libPath) return caBindings;
  const lib = koffi.load(libPath);
  // CK_RV is unsigned long
  const CK_RV = CK_ULONG_T;
  const CA_EncapsulateKey = lib.func("CA_EncapsulateKey", CK_RV, [
    CK_ULONG_T, // hSession
    PTR, // pMechanism
    CK_ULONG_T, // hPublicKey
    PTR, // pTemplate
    CK_ULONG_T, // ulAttributeCount
    PTR, // pCiphertext
    PTR, // pulCiphertextLen
    PTR, // phKey
  ]);
  const CA_DecapsulateKey = lib.func("CA_DecapsulateKey", CK_RV, [
    CK_ULONG_T,
    PTR,
    CK_ULONG_T,
    PTR,
    CK_ULONG_T,
    PTR,
    CK_ULONG_T,
    PTR,
  ]);
  caBindings = { libPath, CA_EncapsulateKey, CA_DecapsulateKey };
  return caBindings;
}

function packMechanism(mechType, paramBuf) {
  const out = Buffer.alloc(koffi.sizeof(CkMechanism));
  koffi.encode(out, CkMechanism, {
    mechanism: mechType >>> 0,
    pParameter: paramBuf || null,
    ulParameterLen: paramBuf ? paramBuf.length : 0,
  });
  return out;
}

/**
 * Pack a CK_ATTRIBUTE array. values: [{type, value: Buffer|number|boolean}]
 * Returns { buffer, refs, count }.
 */
function packAttributeArray(attrs) {
  const refs = [];
  const count = attrs.length;
  const stride = koffi.sizeof(CkAttribute);
  const buffer = Buffer.alloc(stride * count);
  for (let i = 0; i < count; i++) {
    const a = attrs[i];
    let valBuf;
    if (Buffer.isBuffer(a.value)) {
      valBuf = a.value;
    } else if (typeof a.value === "boolean") {
      valBuf = Buffer.from([a.value ? 1 : 0]);
    } else if (typeof a.value === "number") {
      valBuf = ulong(a.value);
    } else {
      throw new Error("unsupported attribute value");
    }
    refs.push(valBuf);
    const slice = buffer.subarray(i * stride, (i + 1) * stride);
    koffi.encode(slice, CkAttribute, {
      type: a.type >>> 0,
      pValue: valBuf,
      ulValueLen: valBuf.length,
    });
  }
  return { buffer, refs, count };
}

function encapsulateAesKey(libPath, sessionHandle, publicKeyHandle, ctLen) {
  const ca = getCaBindings(libPath);
  const mech = packMechanism(CKM_ML_KEM, null);
  const tmpl = packAttributeArray([
    { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_SECRET_KEY },
    { type: pkcs11js.CKA_ENCRYPT, value: true },
    { type: pkcs11js.CKA_DECRYPT, value: true },
    { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_AES },
    { type: pkcs11js.CKA_VALUE_LEN, value: 32 },
    { type: pkcs11js.CKA_TOKEN, value: false },
  ]);
  const ciphertext = Buffer.alloc(ctLen);
  const ctLenBuf = ulong(ctLen);
  const keyOut = ulong(0);
  const rv = ca.CA_EncapsulateKey(
    handleToNumber(sessionHandle),
    mech,
    handleToNumber(publicKeyHandle),
    tmpl.buffer,
    tmpl.count,
    ciphertext,
    ctLenBuf,
    keyOut
  );
  if (rv !== 0) {
    const err = new Error("CA_EncapsulateKey failed");
    err.code = rv;
    throw err;
  }
  const outLen =
    CK_ULONG_SIZE === 4 ? ctLenBuf.readUInt32LE(0) : Number(ctLenBuf.readBigUInt64LE(0));
  const keyHandle =
    CK_ULONG_SIZE === 4 ? keyOut.readUInt32LE(0) : Number(keyOut.readBigUInt64LE(0));
  return { ciphertext: ciphertext.subarray(0, outLen), keyHandle };
}

function decapsulateAesKey(libPath, sessionHandle, privateKeyHandle, ciphertext) {
  const ca = getCaBindings(libPath);
  const mech = packMechanism(CKM_ML_KEM, null);
  const tmpl = packAttributeArray([
    { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_SECRET_KEY },
    { type: pkcs11js.CKA_ENCRYPT, value: true },
    { type: pkcs11js.CKA_DECRYPT, value: true },
    { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_AES },
    { type: pkcs11js.CKA_VALUE_LEN, value: 32 },
    { type: pkcs11js.CKA_TOKEN, value: false },
  ]);
  const keyOut = ulong(0);
  const rv = ca.CA_DecapsulateKey(
    handleToNumber(sessionHandle),
    mech,
    handleToNumber(privateKeyHandle),
    tmpl.buffer,
    tmpl.count,
    ciphertext,
    ciphertext.length,
    keyOut
  );
  if (rv !== 0) {
    const err = new Error("CA_DecapsulateKey failed");
    err.code = rv;
    throw err;
  }
  return CK_ULONG_SIZE === 4
    ? keyOut.readUInt32LE(0)
    : Number(keyOut.readBigUInt64LE(0));
}

function numberToHandle(n) {
  return ulong(n);
}

module.exports = {
  pkcs11js,
  usageAndExit,
  withPqcSession,
  tokenLabel,
  findSlot,
  ckR,
  handleToNumber,
  numberToHandle,
  destroyPair,
  generateMlDsaKeyPair,
  generateMlKemKeyPair,
  packSignAdditionalContext,
  packHashSignAdditionalContext,
  encapsulateAesKey,
  decapsulateAesKey,
  CKM_ML_KEM_KEY_PAIR_GEN,
  CKM_ML_KEM,
  CKM_ML_DSA_KEY_PAIR_GEN,
  CKM_ML_DSA,
  CKM_HASH_ML_DSA,
  CKM_HASH_ML_DSA_SHA3_512,
  CKM_HSS_KEY_PAIR_GEN,
  CKM_HSS,
  CKM_EXTMU_ML_DSA,
  CKM_SHA256,
  CKM_SHA3_512,
  CKM_AES_KWP,
  CKK_HSS,
  CKK_ML_KEM,
  CKK_ML_DSA,
  CKA_HSS_LEVELS,
  CKA_HSS_LMS_TYPES,
  CKA_HSS_LMOTS_TYPES,
  CKA_HSS_KEYS_REMAINING,
  CKA_PARAMETER_SET,
  CKA_ENCAPSULATE,
  CKA_DECAPSULATE,
  CKP_ML_DSA_44,
  CKP_ML_DSA_65,
  CKP_ML_DSA_87,
  CKP_ML_KEM_512,
  CKP_ML_KEM_768,
  CKP_ML_KEM_1024,
  CKH_HEDGE_PREFERRED,
  CKH_HEDGE_REQUIRED,
  CKH_DETERMINISTIC_REQUIRED,
  LMS_SHA256_M32_H5,
  LMOTS_SHA256_N32_W8,
  ML_DSA_SETS,
  ML_KEM_SETS,
  ML_KEM_CT_LEN,
  ulong,
};
