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
 * - Monitor NTP configuration and sync status
 *   (GET /api/lunasa/ntp, /ntp/status, /ntp/servers).
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
    "node monitor_ntp.js <HSM_IP_OR_HOST> <appliance_username>",
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
    for (const path of [
      "/api/lunasa/time",
      "/api/lunasa/ntp",
      "/api/lunasa/ntp/status",
      "/api/lunasa/ntp/servers",
    ]) {
      const res = await restFetch(baseUrl(hostname) + path, {
        method: "GET",
        headers: session.headers,
      });
      console.log("=== " + path + " (HTTP " + res.status + ") ===");
      if (res.status === 200) {
        console.log(JSON.stringify(res.json, null, 2));
      } else {
        console.log(res.text || "(no body)");
      }
      console.log();
    }
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
