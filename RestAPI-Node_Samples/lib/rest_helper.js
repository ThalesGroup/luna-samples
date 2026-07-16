"use strict";

/**
 * Shared helpers for Luna Network HSM REST API Node samples.
 *
 * Env:
 *   LUNA_APPLIANCE_PASSWORD - appliance user password (skips prompt)
 *   LUNA_SO_PASSWORD        - SO password when a sample needs SO login
 *   NODE_TLS_REJECT_UNAUTHORIZED=0 is set by helpers (lab use only)
 */

const readline = require("readline");

// Lab/demo only — Luna appliance often uses private CA / self-signed certs
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

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

async function getAppliancePassword(username) {
  if (process.env.LUNA_APPLIANCE_PASSWORD) {
    return process.env.LUNA_APPLIANCE_PASSWORD;
  }
  return prompt("[" + username + "] Password : ");
}

async function getSoPassword() {
  if (process.env.LUNA_SO_PASSWORD) return process.env.LUNA_SO_PASSWORD;
  return prompt("SECURITY OFFICER PASSWORD : ");
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

async function restFetch(url, options = {}) {
  const res = await fetch(url, options);
  const text = await res.text();
  let json = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch (_) {
      json = text;
    }
  }
  return { status: res.status, headers: res.headers, json, text, raw: res };
}

/**
 * Open appliance session. Returns { headers, cookieHeader, close }.
 */
async function openSession(hostname, username, password) {
  const headers = authHeaders(username, password);
  const url = baseUrl(hostname) + "/auth/session";
  const res = await fetch(url, { method: "POST", headers });
  if (res.status !== 204) {
    throw new Error(
      "Failed to open a session with : " + hostname + " (HTTP " + res.status + ")"
    );
  }
  const setCookie = res.headers.getSetCookie
    ? res.headers.getSetCookie()
    : [];
  // Fallback for older Node: combine set-cookie
  let cookieHeader = setCookie.map((c) => c.split(";")[0]).join("; ");
  if (!cookieHeader) {
    const sc = res.headers.get("set-cookie");
    if (sc) cookieHeader = sc.split(",").map((c) => c.split(";")[0].trim()).join("; ");
  }

  const sessionHeaders = { ...headers };
  if (cookieHeader) sessionHeaders.Cookie = cookieHeader;

  return {
    headers: sessionHeaders,
    cookieHeader,
    async close() {
      await fetch(url, { method: "DELETE", headers: sessionHeaders });
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
  return res.json.hsms[0].id;
}

function usageAndExit(lines) {
  for (const line of lines) console.log(line);
  process.exit(1);
}

module.exports = {
  prompt,
  getAppliancePassword,
  getSoPassword,
  authHeaders,
  baseUrl,
  restFetch,
  openSession,
  getHsmSerial,
  usageAndExit,
};
