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
 * - Read HSM metrics / utilization counters when licensed/supported
 *   (GET /api/lunasa/hsms/{id}/metrics, /utilization, /utilization/bins).
 */

"use strict";
const {
  getAppliancePassword,
  baseUrl,
  restFetch,
  openSession,
  getHsmSerial,
  usageAndExit,
} = require("./lib/rest_helper");

if (process.argv.length !== 4) {
  usageAndExit([
    "",
    "usage :-",
    "node hsm_metrics.js <HSM_IP_OR_HOST> <appliance_username>",
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
    const hsmId = await getHsmSerial(hostname, session.headers);
    const base = baseUrl(hostname) + "/api/lunasa/hsms/" + encodeURIComponent(hsmId);

    for (const suffix of ["/metrics", "/utilization", "/utilization/bins", "/counter"]) {
      const path = base + suffix;
      const res = await restFetch(path, {
        method: "GET",
        headers: session.headers,
      });
      console.log("=== " + path.replace(baseUrl(hostname), "") + " (HTTP " + res.status + ") ===");
      if (res.status === 200) {
        console.log(JSON.stringify(res.json, null, 2));
      } else {
        // 404/501 often means feature not enabled or older firmware
        console.log(res.text || "(unavailable on this appliance/firmware)");
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
