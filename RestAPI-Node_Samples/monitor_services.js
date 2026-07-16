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
 * - List appliance services and their state (GET /api/lunasa/services).
 * - Read-only; does not start/stop services.
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
    "node monitor_services.js <HSM_IP_OR_HOST> <appliance_username>",
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
    const list = await restFetch(baseUrl(hostname) + "/api/lunasa/services", {
      method: "GET",
      headers: session.headers,
    });
    if (list.status !== 200) {
      throw new Error("GET /api/lunasa/services failed. HTTP " + list.status);
    }
    const services = (list.json && list.json.services) || [];
    console.log("ID".padEnd(28), "STATE".padEnd(12), "ENABLED");
    for (const svc of services) {
      const detail = svc.url
        ? await restFetch(baseUrl(hostname) + svc.url, {
            method: "GET",
            headers: session.headers,
          })
        : { status: 0, json: svc };
      const d = detail.status === 200 ? detail.json : svc;
      console.log(
        String(svc.id || d.id || "").padEnd(28),
        String(d.state || d.status || "").padEnd(12),
        d.enabled != null ? String(d.enabled) : d.autostart != null
          ? String(d.autostart)
          : ""
      );
    }
    if (!services.length) {
      console.log(JSON.stringify(list.json, null, 2));
    }
    console.log();
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
