import fs from "node:fs";
import path from "node:path";
import jwt from "jsonwebtoken";
import { writeAuditLog } from "../utils/logger.js";
import { findUserById } from "../services/userStore.js";

// File-backed lists maintained by engine/webapp for containment and test traffic.
const blocklistPath = process.env.BLOCKLIST_PATH || path.join(process.cwd(), "data", "blocklist.json");
const lockedUsersPath = process.env.LOCKED_USERS_PATH || path.join(process.cwd(), "data", "locked_users.json");
const testIpsPath = process.env.TEST_IPS_PATH || path.join(process.cwd(), "logs", "test_ips.json");
const exemptDashboardAdmin = String(process.env.TDR_DASHBOARD_EXEMPT_ADMIN_USER || "admin").trim().toLowerCase();
const allowedDashboardOrigin = String(process.env.CORS_ORIGIN || "http://localhost:5173").trim().toLowerCase();

// Safely read JSON array from disk with empty-list fallback.
function readList(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return [];
  }
}

// Normalize IPv6-mapped IPv4 addresses into standard IPv4 form.
function normalizeIp(ip) {
  const value = String(ip || "");
  return value.startsWith("::ffff:") ? value.slice(7) : value;
}

// Determine if source IP is currently in test mode list.
export function isTestIp(ip) {
  const requestIp = normalizeIp(ip);
  const testIps = readList(testIpsPath);
  const normalizedTestIps = new Set(testIps.map((item) => normalizeIp(item)));
  return normalizedTestIps.has(requestIp);
}

// Allow selected dashboard-admin recovery flows to bypass IP blocklist.
function isDashboardAdminExempt(req) {
  const endpoint = String(req.path || "");
  const requestOrigin = String(req.headers.origin || "").trim().toLowerCase();
  const isDashboardOrigin = requestOrigin && requestOrigin === allowedDashboardOrigin;

  // Allow CSRF token issuance so the exempt admin can always log in via dashboard.
  if (endpoint === "/api/csrf-token" && isDashboardOrigin) {
    return true;
  }

  // Allow exempt admin login attempts even if source IP is blocklisted.
  if (endpoint === "/api/auth/login" && isDashboardOrigin) {
    const attemptedUsername = String(req.body?.username || "").trim().toLowerCase();
    if (attemptedUsername && attemptedUsername === exemptDashboardAdmin) {
      return true;
    }
  }

  // Allow dashboard auth/profile endpoints to proceed to route-level auth checks.
  // This prevents IP block middleware from breaking admin session recovery flows.
  if (
    isDashboardOrigin
    && (endpoint === "/api/auth/me" || endpoint === "/api/auth/settings" || endpoint.startsWith("/api/auth/users"))
  ) {
    return true;
  }

  // Allow refresh for exempt admin based on refresh token subject.
  if (endpoint === "/api/auth/refresh" && isDashboardOrigin) {
    const refreshToken = String(req.body?.refreshToken || "").trim();
    if (refreshToken) {
      try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = findUserById(decoded?.sub);
        const username = String(user?.username || "").trim().toLowerCase();
        const role = String(user?.role || "");
        if (role === "admin" && username === exemptDashboardAdmin) {
          return true;
        }
      } catch {
        // fall through
      }
    }
  }

  // Allow authenticated dashboard/admin requests when token belongs to exempt admin.
  const authHeader = String(req.headers.authorization || "");
  if (!authHeader.startsWith("Bearer ")) {
    return false;
  }
  const token = authHeader.slice(7).trim();
  if (!token) {
    return false;
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    const username = String(decoded?.username || "").trim().toLowerCase();
    const role = String(decoded?.role || "");
    return role === "admin" && username === exemptDashboardAdmin;
  } catch {
    return false;
  }
}

// Block requests from denylisted IPs unless explicit exempt-admin flow applies.
export function blocklistGuard(req, res, next) {
  const blockedIps = readList(blocklistPath);
  const normalizedBlocked = new Set(blockedIps.map((ip) => normalizeIp(ip)));
  const requestIp = String(req.ip || "");
  const normalizedRequestIp = normalizeIp(requestIp);

  if (blockedIps.includes(requestIp) || normalizedBlocked.has(normalizedRequestIp)) {
    if (isDashboardAdminExempt(req)) {
      writeAuditLog({
        req,
        event: "BLOCKLIST_BYPASS_EXEMPT_ADMIN",
        success: true,
        metadata: { exemptAdmin: exemptDashboardAdmin }
      });
      next();
      return;
    }
    writeAuditLog({ req, event: "BLOCKLIST_DENY", success: false, errorType: "BlockedIp" });
    res.status(403).json({ error: "IP blocked" });
    return;
  }
  next();
}

// Check whether a specific user ID is marked as locked.
export function isLockedUser(userId) {
  const locked = new Set(readList(lockedUsersPath));
  return locked.has(userId);
}

// Return current locked-user set for admin/listing use cases.
export function getLockedUsers() {
  return new Set(readList(lockedUsersPath));
}
