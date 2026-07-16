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
 * - Read appliance hardware sensors (GET /api/lunasa/sensors).
 * - Pass --values to also GET each /api/lunasa/sensors/{id} (slower).
 */

"use strict";
const {
  getAppliancePassword,
  baseUrl,
  restFetch,
  openSession,
  usageAndExit,
} = require("./lib/rest_helper");

const args = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const wantValues = process.argv.includes("--values");

if (args.length !== 2) {
  usageAndExit([
    "",
    "usage :-",
    "node monitor_sensors.js <HSM_IP_OR_HOST> <appliance_username> [--values]",
    "",
  ]);
}

const hostname = args[0];
const username = args[1];

async function getOk(session, path, attempts = 5) {
  let last;
  for (let i = 0; i < attempts; i++) {
    last = await restFetch(baseUrl(hostname) + path, {
      method: "GET",
      headers: session.headers,
    });
    if (last.status === 200) return last;
    if (last.status !== 202 && last.status !== 503) break;
    await new Promise((r) => setTimeout(r, 1000 * (i + 1)));
  }
  return last;
}

(async () => {
  const password = await getAppliancePassword(username);
  console.log("Connecting to Luna HSM : [", hostname, "]\n");
  const session = await openSession(hostname, username, password);
  try {
    const list = await getOk(session, "/api/lunasa/sensors");
    if (list.status !== 200) {
      throw new Error("GET /api/lunasa/sensors failed. HTTP " + list.status);
    }
    const sensors = (list.json && list.json.sensors) || [];
    console.log("Sensors:", sensors.length);
    console.log("ID".padEnd(28), "URL");
    for (const s of sensors) {
      console.log(String(s.id || "").padEnd(28), s.url || "");
    }

    if (wantValues && sensors.length) {
      console.log("\n=== Sensor values (--values) ===");
      console.log(
        "ID".padEnd(28),
        "NAME".padEnd(28),
        "VALUE".padEnd(12),
        "STATUS"
      );
      for (const s of sensors) {
        if (!s.url) continue;
        const detail = await getOk(session, s.url, 3);
        const d = detail.status === 200 ? detail.json : {};
        console.log(
          String(s.id || "").padEnd(28),
          String(d.name || d.label || "").padEnd(28),
          String(d.value != null ? d.value : d.reading != null ? d.reading : "").padEnd(12),
          d.status || d.state || (detail.status !== 200 ? "HTTP " + detail.status : "")
        );
      }
    } else if (sensors.length) {
      console.log("\n(tip: pass --values to fetch each sensor reading)");
    }
    console.log();
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
