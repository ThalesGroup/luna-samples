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
 * - Show webServer status and blocklist summary (read-only).
 *   GET /api/lunasa/webServer, /webServer/blocklist (or legacy blacklist).
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
    "node monitor_webserver.js <HSM_IP_OR_HOST> <appliance_username>",
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
    const ws = await restFetch(baseUrl(hostname) + "/api/lunasa/webServer", {
      method: "GET",
      headers: session.headers,
    });
    console.log("=== /api/lunasa/webServer (HTTP " + ws.status + ") ===");
    if (ws.status === 200) console.log(JSON.stringify(ws.json, null, 2));
    else console.log(ws.text || "(no body)");
    console.log();

    let bl = await restFetch(
      baseUrl(hostname) + "/api/lunasa/webServer/blocklist",
      { method: "GET", headers: session.headers }
    );
    let pathUsed = "/api/lunasa/webServer/blocklist";
    if (bl.status === 404) {
      pathUsed = "/api/lunasa/webServer/blacklist";
      bl = await restFetch(baseUrl(hostname) + pathUsed, {
        method: "GET",
        headers: session.headers,
      });
    }
    console.log("=== " + pathUsed + " (HTTP " + bl.status + ") ===");
    if (bl.status === 200) console.log(JSON.stringify(bl.json, null, 2));
    else if (bl.status === 403) {
      console.log("(forbidden for this role — admin often required)");
    } else {
      console.log(bl.text || "(no body)");
    }
    console.log();
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
