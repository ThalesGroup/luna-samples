"use strict";

/**
 * Shared helpers for Node-PKCS11 Luna samples (graphene-pk11).
 *
 * Env:
 *   P11_LIB          - path to cryptoki.dll / libCryptoki2_64.so
 *                      (default: C:\Program Files\SafeNet\LunaClient\cryptoki.dll on Windows,
 *                       /usr/safenet/lunaclient/lib/libCryptoki2_64.so elsewhere)
 *   LUNA_PIN         - Crypto Officer PIN (skips interactive prompt)
 *   SAMPLE_PLAINTEXT - optional plaintext for encrypt/sign demos
 */

const readline = require("readline");
const graphene = require("graphene-pk11");

const DEFAULT_P11_LIB =
  process.platform === "win32"
    ? "C:\\Program Files\\SafeNet\\LunaClient\\cryptoki.dll"
    : "/usr/safenet/lunaclient/lib/libCryptoki2_64.so";

/** Luna vendor-defined CKM_AES_KWP */
const CKM_AES_KWP = 0x80000171;

function getP11Lib() {
  return process.env.P11_LIB || DEFAULT_P11_LIB;
}

function requireP11Lib() {
  if (!process.env.P11_LIB) {
    console.log("*** P11_LIB environment variable not set — using default. ***");
    console.log("> set P11_LIB=" + DEFAULT_P11_LIB + "\n");
  }
  return getP11Lib();
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

/** Prompt without echoing characters (best-effort). */
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

async function getPin(promptText = "Crypto Officer Password: ") {
  if (process.env.LUNA_PIN) return process.env.LUNA_PIN;
  return promptSecret(promptText);
}

async function getPlaintext(promptText = "Enter plaintext: ", maxLen) {
  let text = process.env.SAMPLE_PLAINTEXT;
  if (text == null || text === "") {
    text = await prompt(promptText);
  }
  if (maxLen != null && Buffer.byteLength(text, "utf8") > maxLen) {
    throw new Error(`Plaintext too long (max ${maxLen} bytes).`);
  }
  return text;
}

function findSlotByLabel(mod, label) {
  const slots = mod.getSlots(true);
  for (let i = 0; i < slots.length; i++) {
    const slot = slots.items(i);
    try {
      const tokenLabel = String(slot.getToken().label).trim();
      if (tokenLabel === label) return slot;
    } catch (_) {
      /* skip */
    }
  }
  return null;
}

function findObjectsByLabel(session, label, objectClass) {
  const template = { label };
  if (objectClass != null) template.class = objectClass;
  const objs = session.find(template);
  const out = [];
  for (let i = 0; i < objs.length; i++) out.push(objs.items(i));
  return out;
}

function findKeyByLabel(session, label, objectClass) {
  const objs = findObjectsByLabel(session, label, objectClass);
  if (!objs.length) throw new Error(`${label} not found.`);
  return objs[0];
}

/**
 * Load module, open RW session, login, run fn(session, mod, slot), then cleanup.
 */
async function withSession(slotLabel, fn) {
  const pkcs11Library = requireP11Lib();
  const pin = await getPin();

  const mod = graphene.Module.load(pkcs11Library, "Luna");
  mod.initialize();

  try {
    console.log("PKCS11 library found at : ", pkcs11Library);

    const slot = findSlotByLabel(mod, slotLabel);
    if (!slot) {
      console.log("Incorrect token label.\n");
      process.exitCode = 1;
      return;
    }
    console.log("Token found : ", slotLabel);

    const session = slot.open(
      graphene.SessionFlag.RW_SESSION | graphene.SessionFlag.SERIAL_SESSION
    );
    try {
      session.login(pin);
      console.log("Login success.");
      await fn(session, mod, slot);
    } finally {
      try {
        session.logout();
      } catch (_) {
        /* already logged out */
      }
      session.close();
    }
  } catch (err) {
    const msg = err && err.message ? err.message : String(err);
    if (/CKR_PIN_INCORRECT|PIN_INCORRECT|pin incorrect/i.test(msg)) {
      console.log("Incorrect crypto officer pin.\n");
    } else {
      console.error(err);
    }
    process.exitCode = 1;
  } finally {
    try {
      mod.finalize();
    } catch (_) {
      /* ignore */
    }
  }
}

function usageAndExit(lines) {
  for (const line of lines) console.log(line);
  process.exit(1);
}

function toHex(buf) {
  return Buffer.from(buf).toString("hex");
}

module.exports = {
  graphene,
  CKM_AES_KWP,
  DEFAULT_P11_LIB,
  getP11Lib,
  requireP11Lib,
  prompt,
  promptSecret,
  getPin,
  getPlaintext,
  findSlotByLabel,
  findObjectsByLabel,
  findKeyByLabel,
  withSession,
  usageAndExit,
  toHex,
};
