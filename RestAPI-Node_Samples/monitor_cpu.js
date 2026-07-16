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
 * - Monitor appliance CPU utilization (GET /api/lunasa/cpu).
 * - Optionally list top processes (GET /api/lunasa/cpu/process/processes).
 */

"use strict";
const {
  getAppliancePassword,
  baseUrl,
  restFetch,
  openSession,
  usageAndExit,
} = require("./lib/rest_helper");

if (process.argv.length !== 4) {
  usageAndExit([
    "",
    "usage :-",
    "node monitor_cpu.js <HSM_IP_OR_HOST> <appliance_username>",
    "",
  ]);
}

const hostname = process.argv[2];
const username = process.argv[3];

(async () => {
  const password = await getAppliancePassword(username);
  console.log("Connecting to Luna HSM : [", hostname, "]\n");
  const session = await openSession(hostname, username, password);
  try {
    const cpu = await restFetch(baseUrl(hostname) + "/api/lunasa/cpu", {
      method: "GET",
      headers: session.headers,
    });
    if (cpu.status !== 200) {
      throw new Error("GET /api/lunasa/cpu failed. HTTP " + cpu.status);
    }
    console.log("=== CPU ===");
    console.log(JSON.stringify(cpu.json, null, 2));
    console.log();

    // Newer appliances expose /cpu/process/processes; older ones used /cpu/processes
    let procs = await restFetch(
      baseUrl(hostname) + "/api/lunasa/cpu/process/processes",
      { method: "GET", headers: session.headers }
    );
    if (procs.status !== 200) {
      procs = await restFetch(baseUrl(hostname) + "/api/lunasa/cpu/processes", {
        method: "GET",
        headers: session.headers,
      });
    }
    if (procs.status === 200) {
      const list =
        (procs.json && (procs.json.processes || procs.json)) || procs.json;
      console.log("=== Processes (sample) ===");
      const arr = Array.isArray(list) ? list : [];
      const sample = arr.slice(0, 10);
      console.log(JSON.stringify(sample.length ? sample : procs.json, null, 2));
      if (arr.length > 10) console.log("... (" + arr.length + " total)");
    } else {
      console.log(
        "(process list unavailable: HTTP " + procs.status + " — may need newer API)"
      );
    }
    console.log();
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
