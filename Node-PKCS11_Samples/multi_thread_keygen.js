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
 * - Multi-session parallel RSA keypair generation (same model as multi_thread_signing).
 * - Main: C_Initialize once, login once. Workers: C_OpenSession, generate, close.
 * - Optional --compare mode: time single-thread vs multi-thread for N keypairs.
 * - Optional --token: store keypairs on the token (kept; print labels). Add --cleanup to destroy.
 * - Default: session objects (token=false) that vanish when sessions close.
 */

"use strict";
const { Worker, isMainThread, workerData, parentPort } = require("worker_threads");
const {
  graphene,
  requireP11Lib,
  findSlotByLabel,
  getPin,
  usageAndExit,
} = require("./lib/helper");

const KEY_BITS = 2048;

function safeInitialize(mod) {
  try {
    mod.initialize();
  } catch (err) {
    const msg = err && err.message ? err.message : String(err);
    if (!/ALREADY_INITIALIZED|already initialized/i.test(msg)) throw err;
  }
}

function generateRsaKeypair(session, label, onToken) {
  return session.generateKeyPair(
    graphene.KeyGenMechanism.RSA,
    {
      keyType: graphene.KeyType.RSA,
      modulusBits: KEY_BITS,
      publicExponent: Buffer.from([0x01, 0x00, 0x01]),
      label,
      token: onToken,
      verify: true,
    },
    {
      keyType: graphene.KeyType.RSA,
      label,
      token: onToken,
      private: true,
      sensitive: true,
      sign: true,
      extractable: false,
    }
  );
}

function objectLabel(obj) {
  try {
    if (typeof obj.get === "function") {
      const v = obj.get("label");
      return v == null ? "" : String(v);
    }
  } catch (_) {}
  try {
    return obj.label == null ? "" : String(obj.label);
  } catch (_) {
    return "";
  }
}

/** Destroy pub/priv objects whose labels start with prefix (token objects). */
function destroyKeysByPrefix(session, prefix) {
  let destroyed = 0;
  for (const cls of [
    graphene.ObjectClass.PUBLIC_KEY,
    graphene.ObjectClass.PRIVATE_KEY,
  ]) {
    const objs = session.find({ class: cls, token: true });
    // Snapshot handles/labels first — destroy mutates the find set.
    const matches = [];
    for (let i = 0; i < objs.length; i++) {
      const obj = objs.items(i);
      const label = objectLabel(obj);
      if (label.indexOf(prefix) === 0) matches.push(obj);
    }
    for (const obj of matches) {
      obj.destroy();
      destroyed++;
    }
  }
  return destroyed;
}

/** Destroy pub+priv for each exact label (preferred when labels are known). */
function destroyKeysByLabels(session, labels) {
  let destroyed = 0;
  for (const label of labels) {
    for (const cls of [
      graphene.ObjectClass.PUBLIC_KEY,
      graphene.ObjectClass.PRIVATE_KEY,
    ]) {
      const objs = session.find({ class: cls, label, token: true });
      for (let i = 0; i < objs.length; i++) {
        objs.items(i).destroy();
        destroyed++;
      }
    }
  }
  return destroyed;
}

if (!isMainThread) {
  (async () => {
    const { p11Lib, slotLabel, keysPerThread, threadId, runId, onToken } =
      workerData;
    const mod = graphene.Module.load(p11Lib, "Luna");
    safeInitialize(mod);
    const slot = findSlotByLabel(mod, slotLabel);
    if (!slot) throw new Error("slot not found: " + slotLabel);
    const session = slot.open(
      graphene.SessionFlag.RW_SESSION | graphene.SessionFlag.SERIAL_SESSION
    );
    try {
      const labels = [];
      const t0 = process.hrtime.bigint();
      for (let i = 0; i < keysPerThread; i++) {
        const label = "NodeMTKG_" + runId + "_t" + threadId + "_" + i;
        generateRsaKeypair(session, label, onToken);
        labels.push(label);
      }
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      parentPort.postMessage({
        ok: true,
        threadId,
        keys: keysPerThread,
        ms,
        labels,
      });
    } finally {
      session.close();
    }
  })().catch((err) => {
    parentPort.postMessage({
      ok: false,
      error: err && err.message ? err.message : String(err),
      threadId: workerData.threadId,
    });
  });
  return;
}

function usage() {
  usageAndExit([
    "Usage:",
    "node multi_thread_keygen.js <slot_label> <num_threads> <keys_per_thread> [--token] [--cleanup]",
    "node multi_thread_keygen.js <slot_label> --compare <total_keys> [--token] [--cleanup]",
    "",
    "--token   : CKA_TOKEN=true (keys persist on the partition)",
    "--cleanup : destroy generated token keys at the end (only with --token)",
    "",
    "Examples:",
    "node multi_thread_keygen.js myPartition 4 2",
    "node multi_thread_keygen.js myPartition 10 1 --token",
    "node multi_thread_keygen.js myPartition 10 1 --token --cleanup",
    "node multi_thread_keygen.js myPartition --compare 5\n",
  ]);
}

console.log("\nmulti_thread_keygen.js\n");

const argv = process.argv.slice(2);
const onToken = argv.includes("--token");
const doCleanup = argv.includes("--cleanup");
const args = argv.filter((a) => a !== "--token" && a !== "--cleanup");
if (doCleanup && !onToken) {
  console.error("--cleanup requires --token.\n");
  process.exit(1);
}

const slotLabel = args[0];
const compareMode = args[1] === "--compare";
let nThreads;
let keysPerThread;
let totalKeys;

if (!slotLabel) usage();

if (compareMode) {
  if (args.length !== 3) usage();
  totalKeys = parseInt(args[2], 10);
  if (!(totalKeys > 0)) {
    console.error("total_keys must be a positive integer.\n");
    process.exit(1);
  }
} else {
  if (args.length !== 3) usage();
  nThreads = parseInt(args[1], 10);
  keysPerThread = parseInt(args[2], 10);
  if (!(nThreads > 0) || !(keysPerThread > 0)) {
    console.error("num_threads and keys_per_thread must be positive integers.\n");
    process.exit(1);
  }
  totalKeys = nThreads * keysPerThread;
}

function runWorkers(p11Lib, threads, kpt, runId) {
  const workers = [];
  for (let i = 0; i < threads; i++) {
    workers.push(
      new Promise((resolve) => {
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
            keysPerThread: kpt,
            threadId: i,
            runId,
            onToken,
          },
        });
        w.on("message", done);
        w.on("error", (err) =>
          done({ ok: false, threadId: i, error: err.message })
        );
        w.on("exit", (code) => {
          if (code !== 0)
            done({ ok: false, threadId: i, error: "worker exit " + code });
        });
      })
    );
  }
  return Promise.all(workers);
}

function summarize(label, results, wallMs) {
  let failed = 0;
  let keys = 0;
  for (const r of results) {
    if (r.ok) {
      keys += r.keys;
      console.log(
        "  --> Thread",
        r.threadId,
        "generated",
        r.keys,
        "keypair(s) in",
        r.ms.toFixed(1),
        "ms"
      );
    } else {
      failed++;
      console.log("  --> Thread", r.threadId, "FAILED:", r.error);
    }
  }
  const kind = onToken ? "token" : "session";
  console.log(
    "\n>",
    label + ":",
    keys,
    "RSA-" + KEY_BITS,
    kind,
    "keypairs in",
    wallMs.toFixed(1),
    "ms wall time",
    failed ? "(" + failed + " thread(s) failed)" : ""
  );
  console.log(
    "  avg",
    keys ? (wallMs / keys).toFixed(1) : "n/a",
    "ms per keypair (wall)\n"
  );
  return { failed, keys, wallMs };
}

(async () => {
  const p11Lib = requireP11Lib();
  const pin = await getPin();
  const mod = graphene.Module.load(p11Lib, "Luna");
  mod.initialize();
  let session;
  let slot;
  let activeRunPrefix = null;
  try {
    console.log("PKCS11 library found at : ", p11Lib);
    slot = findSlotByLabel(mod, slotLabel);
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
      "Generating RSA-" +
        KEY_BITS +
        " keypairs (token=" +
        onToken +
        ").\n"
    );

    if (compareMode) {
      const runIdSingle = "s" + Date.now().toString(36);
      const prefixSingle = "NodeMTKG_" + runIdSingle;
      activeRunPrefix = prefixSingle;

      console.log("--- Single-thread (" + totalKeys + " keys on 1 session) ---");
      let t0 = process.hrtime.bigint();
      for (let i = 0; i < totalKeys; i++) {
        generateRsaKeypair(session, prefixSingle + "_" + i, onToken);
        console.log("  --> key", i + 1 + "/" + totalKeys, "generated");
      }
      const singleMs = Number(process.hrtime.bigint() - t0) / 1e6;
      const kind = onToken ? "token" : "session";
      console.log(
        "\n> single-thread:",
        totalKeys,
        "RSA-" + KEY_BITS,
        kind,
        "keypairs in",
        singleMs.toFixed(1),
        "ms"
      );
      console.log("  avg", (singleMs / totalKeys).toFixed(1), "ms per keypair\n");

      if (onToken && doCleanup) {
        const n = destroyKeysByPrefix(session, prefixSingle);
        console.log("Cleaned", n, "single-thread token object(s).\n");
      } else if (onToken) {
        console.log(
          "Token keys kept (prefix",
          prefixSingle + "). Use --cleanup to destroy.\n"
        );
      }

      const runIdMulti = "m" + Date.now().toString(36);
      const prefixMulti = "NodeMTKG_" + runIdMulti;
      activeRunPrefix = prefixMulti;

      console.log(
        "--- Multi-thread (" + totalKeys + " keys, " + totalKeys + " sessions) ---"
      );
      t0 = process.hrtime.bigint();
      const multi = await runWorkers(p11Lib, totalKeys, 1, runIdMulti);
      const multiWall = Number(process.hrtime.bigint() - t0) / 1e6;
      const m = summarize("multi-thread", multi, multiWall);

      if (onToken && doCleanup) {
        try {
          session.logout();
        } catch (_) {}
        session.close();
        session = slot.open(
          graphene.SessionFlag.RW_SESSION | graphene.SessionFlag.SERIAL_SESSION
        );
        session.login(pin, graphene.UserType.USER);
        const n = destroyKeysByPrefix(session, prefixMulti);
        console.log("Cleaned", n, "multi-thread token object(s).\n");
        activeRunPrefix = null;
      } else if (onToken) {
        const kept = [];
        for (const r of multi) {
          if (r.ok && Array.isArray(r.labels)) kept.push(...r.labels);
        }
        console.log(
          "Token keys kept:",
          kept.length,
          "keypair(s). Prefix",
          prefixMulti + ". Use --cleanup to destroy.\n"
        );
        activeRunPrefix = null;
      }

      if (m.failed) {
        process.exitCode = 1;
        return;
      }
      let multiSpan = 0;
      for (const r of multi) {
        if (r.ok && r.ms > multiSpan) multiSpan = r.ms;
      }
      const speedupWall = multiWall > 0 ? singleMs / multiWall : 0;
      const speedupSpan = multiSpan > 0 ? singleMs / multiSpan : 0;
      console.log(
        "=== Comparison (" + totalKeys + " RSA-" + KEY_BITS + " keypairs) ==="
      );
      console.log("  single-thread          :", singleMs.toFixed(1), "ms");
      console.log(
        "  multi-thread (wall)    :",
        multiWall.toFixed(1),
        "ms  (includes worker start / open session)"
      );
      console.log(
        "  multi-thread (keygen)  :",
        multiSpan.toFixed(1),
        "ms  (slowest worker; HSM-parallel span)"
      );
      console.log(
        "  speedup vs wall        :",
        speedupWall.toFixed(2) + "x  (" + (singleMs - multiWall).toFixed(1) + " ms)"
      );
      console.log(
        "  speedup vs keygen span :",
        speedupSpan.toFixed(2) + "x  (" + (singleMs - multiSpan).toFixed(1) + " ms)\n"
      );
      process.exitCode = 0;
      return;
    }

    const runId = Date.now().toString(36);
    activeRunPrefix = "NodeMTKG_" + runId;
    console.log(
      "Starting",
      nThreads,
      "worker threads,",
      keysPerThread,
      "keypair(s) each.\n"
    );
    const t0 = process.hrtime.bigint();
    const results = await runWorkers(p11Lib, nThreads, keysPerThread, runId);
    const wallMs = Number(process.hrtime.bigint() - t0) / 1e6;
    const { failed } = summarize("run", results, wallMs);

    if (onToken) {
      const labels = [];
      for (const r of results) {
        if (r.ok && Array.isArray(r.labels)) labels.push(...r.labels);
      }
      if (doCleanup) {
        try {
          session.logout();
        } catch (_) {}
        session.close();
        session = slot.open(
          graphene.SessionFlag.RW_SESSION | graphene.SessionFlag.SERIAL_SESSION
        );
        session.login(pin, graphene.UserType.USER);
        let n = destroyKeysByLabels(session, labels);
        if (n === 0 && activeRunPrefix) {
          n = destroyKeysByPrefix(session, activeRunPrefix);
        }
        console.log(
          "Token cleanup: destroyed",
          n,
          "object(s)",
          labels.length ? "(" + labels.length + " keypair labels)" : "",
          "\n"
        );
      } else {
        console.log("Token keys kept on partition:");
        for (const lab of labels) console.log("  ", lab);
        console.log("(Use --token --cleanup to destroy after generate.)\n");
      }
      activeRunPrefix = null;
    }

    process.exitCode = failed ? 1 : 0;
  } catch (err) {
    console.error(err);
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
})();
