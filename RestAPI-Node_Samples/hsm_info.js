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
 * - Show HSM identity / firmware / storage summary for monitoring
 *   (GET /api/lunasa/hsms, /hsms/{id}, firmware, storageSpace, licenses).
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
    "node hsm_info.js <HSM_IP_OR_HOST> <appliance_username>",
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

    for (const suffix of ["", "/firmware", "/storageSpace", "/licenses", "/policies"]) {
      const path = base + suffix;
      const res = await restFetch(path, {
        method: "GET",
        headers: session.headers,
      });
      console.log("=== " + path.replace(baseUrl(hostname), "") + " (HTTP " + res.status + ") ===");
      if (res.status === 200) {
        const body = res.json;
        // policies can be huge — summarize
        if (suffix === "/policies" && body && Array.isArray(body.policies)) {
          console.log("policies count:", body.policies.length);
          console.log(JSON.stringify(body.policies.slice(0, 5), null, 2));
          if (body.policies.length > 5) console.log("... (" + body.policies.length + " total)");
        } else {
          console.log(JSON.stringify(body, null, 2));
        }
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
