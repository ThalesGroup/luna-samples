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
 * - One-shot read-only monitoring overview: appliance, CPU, memory, disk,
 *   services, NTP status, HSM identity, and storage.
 * - Safe for Monitor-role users; no create/delete/start/stop actions.
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
    "node monitor_overview.js <HSM_IP_OR_HOST> <appliance_username>",
    "",
  ]);
}

const hostname = process.argv[2];
const username = process.argv[3];

async function getJson(session, path) {
  const res = await restFetch(baseUrl(hostname) + path, {
    method: "GET",
    headers: session.headers,
  });
  return { path, status: res.status, json: res.json };
}

function brief(obj, keys) {
  if (!obj || typeof obj !== "object") return obj;
  const out = {};
  for (const k of keys) {
    if (obj[k] !== undefined) out[k] = obj[k];
  }
  return Object.keys(out).length ? out : obj;
}

(async () => {
  const password = await getAppliancePassword(username);
  console.log("Connecting to Luna HSM : [", hostname, "]\n");
  const session = await openSession(hostname, username, password);
  try {
    const appliance = await getJson(session, "/api/lunasa");
    const cpu = await getJson(session, "/api/lunasa/cpu");
    const memory = await getJson(session, "/api/lunasa/memory");
    const disk = await getJson(session, "/api/lunasa/disk");
    const services = await getJson(session, "/api/lunasa/services");
    const ntpStatus = await getJson(session, "/api/lunasa/ntp/status");
    const time = await getJson(session, "/api/lunasa/time");
    const sensors = await getJson(session, "/api/lunasa/sensors");

    let hsmId = null;
    let hsm = null;
    let storage = null;
    try {
      hsmId = await getHsmSerial(hostname, session.headers);
      hsm = await getJson(session, "/api/lunasa/hsms/" + encodeURIComponent(hsmId));
      storage = await getJson(
        session,
        "/api/lunasa/hsms/" + encodeURIComponent(hsmId) + "/storageSpace"
      );
    } catch (e) {
      hsm = { path: "/api/lunasa/hsms", status: 0, json: { error: e.message } };
    }

    const svcList =
      (services.json && services.json.services) ||
      (Array.isArray(services.json) ? services.json : []);
    const running = svcList.filter(
      (s) =>
        String(s.state || s.status || "").toLowerCase() === "running" ||
        String(s.state || s.status || "").toLowerCase() === "started"
    ).length;

    console.log("=== Monitoring overview ===\n");
    console.log("Appliance:", appliance.status === 200 ? brief(appliance.json, [
      "hostname",
      "name",
      "version",
      "softwareVersion",
      "applianceVersion",
      "model",
      "serial",
      "serialNumber",
    ]) : "HTTP " + appliance.status);
    console.log("Time:     ", time.status === 200 ? time.json : "HTTP " + time.status);
    console.log("NTP:      ", ntpStatus.status === 200 ? ntpStatus.json : "HTTP " + ntpStatus.status);
    console.log("CPU:      ", cpu.status === 200 ? cpu.json : "HTTP " + cpu.status);
    console.log("Memory:   ", memory.status === 200 ? memory.json : "HTTP " + memory.status);
    console.log("Disk:     ", disk.status === 200 ? disk.json : "HTTP " + disk.status);
    console.log(
      "Services: ",
      services.status === 200
        ? svcList.length + " listed (" + running + " running/started)"
        : "HTTP " + services.status
    );
    console.log(
      "Sensors:  ",
      sensors.status === 200
        ? ((sensors.json && sensors.json.sensors) || []).length + " sensors"
        : "HTTP " + sensors.status
    );
    console.log("HSM id:   ", hsmId || "(none)");
    if (hsm && hsm.status === 200) {
      console.log(
        "HSM:      ",
        brief(hsm.json, [
          "label",
          "name",
          "model",
          "firmwareVersion",
          "firmware",
          "state",
          "status",
          "fips",
          "authentication",
        ])
      );
    }
    if (storage && storage.status === 200) {
      console.log("Storage:  ", storage.json);
    }
    console.log();
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
