import fs from "node:fs";
import path from "node:path";
import { writeAuditLog } from "../utils/logger.js";

const blocklistPath = process.env.BLOCKLIST_PATH || path.join(process.cwd(), "data", "blocklist.json");
const lockedUsersPath = process.env.LOCKED_USERS_PATH || path.join(process.cwd(), "data", "locked_users.json");

function readList(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return [];
  }
}

function normalizeIp(ip) {
  const value = String(ip || "");
  return value.startsWith("::ffff:") ? value.slice(7) : value;
}

export function blocklistGuard(req, res, next) {
  const blockedIps = readList(blocklistPath);
  const normalizedBlocked = new Set(blockedIps.map((ip) => normalizeIp(ip)));
  const requestIp = String(req.ip || "");
  const normalizedRequestIp = normalizeIp(requestIp);

  if (blockedIps.includes(requestIp) || normalizedBlocked.has(normalizedRequestIp)) {
    writeAuditLog({ req, event: "BLOCKLIST_DENY", success: false, errorType: "BlockedIp" });
    res.status(403).json({ error: "IP blocked" });
    return;
  }
  next();
}

export function isLockedUser(userId) {
  const locked = new Set(readList(lockedUsersPath));
  return locked.has(userId);
}

export function getLockedUsers() {
  return new Set(readList(lockedUsersPath));
}
