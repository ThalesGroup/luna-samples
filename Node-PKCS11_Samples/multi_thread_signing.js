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
 * - Multi-session parallel signing (mirrors C MultiThread_Signing_demo).
 * - One login, one RSA keypair, then N worker threads each open a session and sign.
 */

"use strict";
const { Worker, isMainThread, workerData, parentPort } = require("worker_threads");
const path = require("path");
const {
  graphene,
  requireP11Lib,
  findSlotByLabel,
  getPin,
  usageAndExit,
} = require("./lib/helper");

if (!isMainThread) {
  (async () => {
    const { p11Lib, slotLabel, pin, keyLabel, ops, threadId } = workerData;
    const mod = graphene.Module.load(p11Lib, "Luna");
    mod.initialize();
    try {
      const slot = findSlotByLabel(mod, slotLabel);
      if (!slot) throw new Error("slot not found: " + slotLabel);
      const session = slot.open(
        graphene.SessionFlag.RW_SESSION | graphene.SessionFlag.SERIAL_SESSION
      );
      try {
        session.login(pin, graphene.UserType.USER);
        const objs = session.find({
          class: graphene.ObjectClass.PRIVATE_KEY,
          label: keyLabel,
        });
        if (!objs.length) throw new Error("private key not found: " + keyLabel);
        const priv = objs.items(0);
        const data = Buffer.from(
          "Hello World, I've been waiting for the chance to see your face."
        );
        for (let i = 0; i < ops; i++) {
          session
            .createSign(graphene.MechanismEnum.SHA256_RSA_PKCS, priv)
            .once(data);
        }
        parentPort.postMessage({
          ok: true,
          threadId,
          ops,
        });
      } finally {
        try {
          session.logout();
        } catch (_) {}
        session.close();
      }
    } finally {
      // Do NOT C_Finalize here — main thread still owns the PKCS#11 library.
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

console.log("\nmulti_thread_signing.js\n");
if (process.argv.length !== 5) {
  usageAndExit([
    "Usage:",
    "node multi_thread_signing.js <slot_label> <num_threads> <ops_per_thread>",
    "",
    "Example:",
    "node multi_thread_signing.js myPartition 4 10\n",
  ]);
}

const slotLabel = process.argv[2];
const nThreads = parseInt(process.argv[3], 10);
const ops = parseInt(process.argv[4], 10);
if (!(nThreads > 0) || !(ops > 0)) {
  console.error("num_threads and ops_per_thread must be positive integers.\n");
  process.exit(1);
}

(async () => {
  const p11Lib = requireP11Lib();
  const pin = await getPin();
  const keyLabel = "NodeMT_" + Date.now().toString(36);
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

    session.generateKeyPair(
      graphene.KeyGenMechanism.RSA,
      {
        keyType: graphene.KeyType.RSA,
        modulusBits: 2048,
        publicExponent: Buffer.from([0x01, 0x00, 0x01]),
        label: keyLabel,
        token: true,
        verify: true,
      },
      {
        keyType: graphene.KeyType.RSA,
        label: keyLabel,
        token: true,
        private: true,
        sensitive: true,
        sign: true,
        extractable: false,
      }
    );
    console.log("RSA-2048 token keypair generated :", keyLabel);
    console.log("Starting", nThreads, "worker threads,", ops, "signs each.\n");

    const workers = [];
    for (let i = 0; i < nThreads; i++) {
      workers.push(
        new Promise((resolve) => {
          const w = new Worker(__filename, {
            workerData: {
              p11Lib,
              slotLabel,
              pin,
              keyLabel,
              ops,
              threadId: i,
            },
          });
          w.on("message", (msg) => resolve(msg));
          w.on("error", (err) =>
            resolve({ ok: false, threadId: i, error: err.message })
          );
          w.on("exit", (code) => {
            if (code !== 0)
              resolve({
                ok: false,
                threadId: i,
                error: "worker exit " + code,
              });
          });
        })
      );
    }
    const results = await Promise.all(workers);
    let failed = 0;
    for (const r of results) {
      if (r.ok) {
        console.log("  --> Thread", r.threadId, "completed", r.ops, "signs.");
      } else {
        failed++;
        console.log("  --> Thread", r.threadId, "FAILED:", r.error);
      }
    }
    console.log(
      "\n>",
      nThreads * ops - failed * ops,
      "sign operations across",
      nThreads,
      "threads.\n"
    );

    try {
      // Worker Initialize can invalidate handles on the original session — re-login to clean up.
      try {
        session.logout();
      } catch (_) {}
      session.close();
      session = slot.open(
        graphene.SessionFlag.RW_SESSION | graphene.SessionFlag.SERIAL_SESSION
      );
      session.login(pin, graphene.UserType.USER);
      const pubs = session.find({
        class: graphene.ObjectClass.PUBLIC_KEY,
        label: keyLabel,
      });
      const privs = session.find({
        class: graphene.ObjectClass.PRIVATE_KEY,
        label: keyLabel,
      });
      for (let i = 0; i < pubs.length; i++) pubs.items(i).destroy();
      for (let i = 0; i < privs.length; i++) privs.items(i).destroy();
      console.log("Token keypair destroyed.\n");
    } catch (cleanupErr) {
      console.log(
        "Cleanup warning:",
        cleanupErr && cleanupErr.message ? cleanupErr.message : cleanupErr
      );
      console.log("(Key label was", keyLabel + " — destroy manually if needed.)\n");
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
      session.close();
    }
    try {
      mod.finalize();
    } catch (_) {}
  }
})();
