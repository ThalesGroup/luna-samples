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
 * - Monitor appliance network summary and per-device stats
 *   (GET /api/lunasa/network, /network/devices, /devices/{id}/stats).
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
    "node monitor_network.js <HSM_IP_OR_HOST> <appliance_username>",
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
    const net = await restFetch(baseUrl(hostname) + "/api/lunasa/network", {
      method: "GET",
      headers: session.headers,
    });
    if (net.status !== 200) {
      throw new Error("GET /api/lunasa/network failed. HTTP " + net.status);
    }
    console.log("=== Network ===");
    console.log(JSON.stringify(net.json, null, 2));
    console.log();

    const devices = await restFetch(
      baseUrl(hostname) + "/api/lunasa/network/devices",
      { method: "GET", headers: session.headers }
    );
    if (devices.status !== 200) {
      console.log("network/devices HTTP " + devices.status);
      return;
    }
    const list = (devices.json && devices.json.devices) || [];
    for (const dev of list) {
      console.log("--- Device:", dev.id, "---");
      const info = await restFetch(baseUrl(hostname) + (dev.url || ("/api/lunasa/network/devices/" + dev.id)), {
        method: "GET",
        headers: session.headers,
      });
      if (info.status === 200) console.log(JSON.stringify(info.json, null, 2));

      const stats = await restFetch(
        baseUrl(hostname) +
          "/api/lunasa/network/devices/" +
          encodeURIComponent(dev.id) +
          "/stats",
        { method: "GET", headers: session.headers }
      );
      if (stats.status === 200) {
        console.log("stats:");
        console.log(JSON.stringify(stats.json, null, 2));
      } else {
        console.log("(stats HTTP " + stats.status + ")");
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
