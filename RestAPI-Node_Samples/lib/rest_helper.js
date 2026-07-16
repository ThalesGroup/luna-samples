"use strict";

/**
 * Shared helpers for Luna Network HSM REST API Node samples.
 *
 * Env:
 *   LUNA_APPLIANCE_PASSWORD - appliance user password (skips prompt)
 *   LUNA_SO_PASSWORD        - SO password when a sample needs SO login
 *   LUNA_REST_INSECURE_TLS  - set to "1" to skip TLS verify (lab/self-signed only)
 *
 * By default TLS certificates are verified. For lab appliances with private CAs,
 * set LUNA_REST_INSECURE_TLS=1 (same idea as Python requests verify=False).
 */

const readline = require("readline");
const https = require("https");

function insecureTlsEnabled() {
  return process.env.LUNA_REST_INSECURE_TLS === "1";
}

function prompt(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

/** Prompt without echoing characters (best-effort; works on typical TTYs). */
function promptSecret(question) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    return prompt(question);
  }
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const stdout = process.stdout;
    stdout.write(question);
    stdin.resume();
    stdin.setRawMode(true);
    stdin.setEncoding("utf8");
    let value = "";
    const onData = (char) => {
      if (char === "\n" || char === "\r" || char === "\u0004") {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener("data", onData);
        stdout.write("\n");
        resolve(value);
        return;
      }
      if (char === "\u0003") {
        stdin.setRawMode(false);
        process.exit(1);
      }
      if (char === "\u007f" || char === "\b") {
        if (value.length) {
          value = value.slice(0, -1);
          stdout.clearLine(0);
          stdout.cursorTo(0);
          stdout.write(question);
        }
        return;
      }
      value += char;
      stdout.write("*");
    };
    stdin.on("data", onData);
  });
}

async function getAppliancePassword(username) {
  if (process.env.LUNA_APPLIANCE_PASSWORD) {
    return process.env.LUNA_APPLIANCE_PASSWORD;
  }
  return promptSecret("[" + username + "] Password : ");
}

async function getSoPassword() {
  if (process.env.LUNA_SO_PASSWORD) return process.env.LUNA_SO_PASSWORD;
  return promptSecret("SECURITY OFFICER PASSWORD : ");
}

function authHeaders(username, password) {
  const authString = Buffer.from(username + ":" + password, "utf8").toString(
    "base64"
  );
  return {
    "Content-type": "application/vnd.safenetinc.lunasa+json;version=",
    Authorization: "Basic " + authString,
  };
}

function baseUrl(hostname) {
  return "https://" + hostname + ":8443";
}

function httpsAgent() {
  if (!insecureTlsEnabled()) return undefined;
  return new https.Agent({ rejectUnauthorized: false });
}

/**
 * HTTPS request helper (supports optional insecure TLS via LUNA_REST_INSECURE_TLS=1).
 * Prefer this over global NODE_TLS_REJECT_UNAUTHORIZED.
 */
function restRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const method = options.method || "GET";
    const headers = { ...(options.headers || {}) };
    const body = options.body != null ? String(options.body) : null;
    if (body != null && headers["Content-Length"] == null) {
      headers["Content-Length"] = Buffer.byteLength(body);
    }

    const req = https.request(
      {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || 443,
        path: u.pathname + u.search,
        method,
        headers,
        agent: httpsAgent(),
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json = null;
          if (text) {
            try {
              json = JSON.parse(text);
            } catch (_) {
              json = text;
            }
          }
          // Minimal fetch-like surface used by samples
          const headersObj = res.headers;
          resolve({
            status: res.statusCode,
            headers: {
              get: (name) => {
                const v = headersObj[String(name).toLowerCase()];
                return Array.isArray(v) ? v.join(", ") : v;
              },
              getSetCookie: () => {
                const sc = headersObj["set-cookie"];
                if (!sc) return [];
                return Array.isArray(sc) ? sc : [sc];
              },
            },
            json,
            text,
            raw: { headers: {
              get: (name) => {
                const v = headersObj[String(name).toLowerCase()];
                return Array.isArray(v) ? v.join(", ") : v;
              },
              getSetCookie: () => {
                const sc = headersObj["set-cookie"];
                if (!sc) return [];
                return Array.isArray(sc) ? sc : [sc];
              },
            } },
          });
        });
      }
    );
    req.on("error", reject);
    if (body != null) req.write(body);
    req.end();
  });
}

async function restFetch(url, options = {}) {
  return restRequest(url, options);
}

/**
 * Open appliance session. Returns { headers, cookieHeader, close }.
 */
async function openSession(hostname, username, password) {
  const headers = authHeaders(username, password);
  const url = baseUrl(hostname) + "/auth/session";
  // Luna OpenAPI: POST /auth/session with Basic auth and empty JSON body
  const res = await restFetch(url, { method: "POST", headers, body: "{}" });
  if (res.status !== 204) {
    const detail =
      res.json && res.json.id
        ? " (" + res.json.id + (res.json.message ? ": " + res.json.message : "") + ")"
        : "";
    throw new Error(
      "Failed to open a session with : " +
        hostname +
        " (HTTP " +
        res.status +
        ")" +
        detail
    );
  }
  const setCookie = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  let cookieHeader = setCookie.map((c) => c.split(";")[0]).join("; ");
  if (!cookieHeader) {
    const sc = res.headers.get("set-cookie");
    if (sc) {
      cookieHeader = sc
        .split(",")
        .map((c) => c.split(";")[0].trim())
        .join("; ");
    }
  }

  const sessionHeaders = { ...headers };
  if (cookieHeader) sessionHeaders.Cookie = cookieHeader;

  return {
    headers: sessionHeaders,
    cookieHeader,
    async close() {
      await restFetch(url, { method: "DELETE", headers: sessionHeaders });
    },
  };
}

async function getHsmSerial(hostname, headers) {
  const res = await restFetch(baseUrl(hostname) + "/api/lunasa/hsms", {
    method: "GET",
    headers,
  });
  if (res.status !== 200) {
    throw new Error("Failed to list HSMs. HTTP " + res.status);
  }
  const hsms = res.json && res.json.hsms;
  if (!Array.isArray(hsms) || hsms.length === 0) {
    throw new Error("No HSMs returned by /api/lunasa/hsms");
  }
  return hsms[0].id;
}

function usageAndExit(lines) {
  for (const line of lines) console.log(line);
  process.exit(1);
}

module.exports = {
  prompt,
  promptSecret,
  getAppliancePassword,
  getSoPassword,
  authHeaders,
  baseUrl,
  restFetch,
  openSession,
  getHsmSerial,
  usageAndExit,
  insecureTlsEnabled,
};
