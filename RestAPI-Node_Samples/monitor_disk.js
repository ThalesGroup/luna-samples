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
 * - Monitor appliance disk usage (GET /api/lunasa/disk and disk/partitions).
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
    "node monitor_disk.js <HSM_IP_OR_HOST> <appliance_username>",
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
    const disk = await restFetch(baseUrl(hostname) + "/api/lunasa/disk", {
      method: "GET",
      headers: session.headers,
    });
    if (disk.status !== 200) {
      throw new Error("GET /api/lunasa/disk failed. HTTP " + disk.status);
    }
    console.log("=== Disk ===");
    console.log(JSON.stringify(disk.json, null, 2));
    console.log();

    const parts = await restFetch(
      baseUrl(hostname) + "/api/lunasa/disk/partitions",
      { method: "GET", headers: session.headers }
    );
    if (parts.status === 200) {
      console.log("=== Disk partitions ===");
      const list = (parts.json && parts.json.partitions) || parts.json;
      if (Array.isArray(list)) {
        console.log(
          "ID".padEnd(12),
          "MOUNT".padEnd(20),
          "SIZE".padEnd(12),
          "USED".padEnd(12),
          "AVAIL"
        );
        for (const p of list) {
          const detail = p.url
            ? await restFetch(baseUrl(hostname) + p.url, {
                method: "GET",
                headers: session.headers,
              })
            : { status: 0, json: p };
          const d = detail.status === 200 ? detail.json : p;
          console.log(
            String(p.id || d.id || "").padEnd(12),
            String(d.mountPoint || d.mount || d.name || "").padEnd(20),
            String(d.size || d.total || "").padEnd(12),
            String(d.used || "").padEnd(12),
            d.available || d.free || ""
          );
        }
      } else {
        console.log(JSON.stringify(parts.json, null, 2));
      }
    } else {
      console.log("disk/partitions HTTP " + parts.status);
    }
    console.log();
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
