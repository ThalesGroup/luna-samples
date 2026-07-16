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
 * - List syslog metadata / available log streams (GET /api/lunasa/syslog,
 *   GET /api/lunasa/syslog/logs). Does not download full log archives.
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
    "node monitor_syslog.js <HSM_IP_OR_HOST> <appliance_username>",
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
    const syslog = await restFetch(baseUrl(hostname) + "/api/lunasa/syslog", {
      method: "GET",
      headers: session.headers,
    });
    console.log("=== /api/lunasa/syslog (HTTP " + syslog.status + ") ===");
    if (syslog.status === 200) console.log(JSON.stringify(syslog.json, null, 2));
    console.log();

    const logs = await restFetch(
      baseUrl(hostname) + "/api/lunasa/syslog/logs",
      { method: "GET", headers: session.headers }
    );
    console.log("=== /api/lunasa/syslog/logs (HTTP " + logs.status + ") ===");
    if (logs.status !== 200) {
      console.log(logs.text || "(no body)");
      return;
    }
    const list = (logs.json && logs.json.logs) || [];
    console.log("ID".padEnd(30), "URL");
    for (const log of list) {
      console.log(String(log.id || "").padEnd(30), log.url || "");
    }
    if (!list.length) console.log(JSON.stringify(logs.json, null, 2));

    const remote = await restFetch(
      baseUrl(hostname) + "/api/lunasa/syslog/remoteHosts",
      { method: "GET", headers: session.headers }
    );
    console.log(
      "\n=== /api/lunasa/syslog/remoteHosts (HTTP " + remote.status + ") ==="
    );
    if (remote.status === 200) console.log(JSON.stringify(remote.json, null, 2));
    console.log();
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
