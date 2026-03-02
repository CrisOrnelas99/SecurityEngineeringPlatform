import { spawn } from "node:child_process";
import crypto from "node:crypto";

const coreBinary = process.env.SECURITY_CORE_BIN || "security_core";

function hashPasswordFallback(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return { hash: `scrypt$${salt}$${derived}` };
}

function verifyPasswordFallback(password, hash) {
  if (typeof hash !== "string") {
    return { valid: false };
  }

  const parts = hash.split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") {
    return { valid: false };
  }

  const [, salt, expectedHex] = parts;
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  const expected = Buffer.from(expectedHex, "hex");
  const actual = Buffer.from(derived, "hex");
  if (expected.length !== actual.length) {
    return { valid: false };
  }
  return { valid: crypto.timingSafeEqual(expected, actual) };
}

function maybeFallback(error, operation, payload) {
  const message = String(error?.message || "");
  const isUnavailable =
    message.includes("Crypto core unavailable") ||
    message.includes("ENOENT") ||
    message.includes("not found");
  if (!isUnavailable) {
    throw error;
  }

  if (operation === "hash-password" && typeof payload?.password === "string") {
    return hashPasswordFallback(payload.password);
  }
  if (operation === "verify-password" && typeof payload?.password === "string") {
    return verifyPasswordFallback(payload.password, payload?.hash);
  }

  throw error;
}

export function callCryptoCore(operation, payload) {
  return new Promise((resolve, reject) => {
    const child = spawn(coreBinary, [operation], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => {
      stdout += data.toString("utf8");
    });

    child.stderr.on("data", (data) => {
      stderr += data.toString("utf8");
    });

    child.on("error", (error) => {
      try {
        resolve(maybeFallback(new Error(`Crypto core unavailable: ${error.message}`), operation, payload));
      } catch (fallbackError) {
        reject(fallbackError);
      }
    });

    child.on("close", (code) => {
      if (code !== 0) {
        try {
          resolve(maybeFallback(new Error(`Crypto core returned ${code}: ${stderr}`), operation, payload));
        } catch (fallbackError) {
          reject(fallbackError);
        }
        return;
      }

      try {
        resolve(JSON.parse(stdout));
      } catch {
        reject(new Error("Crypto core returned invalid JSON"));
      }
    });

    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}
