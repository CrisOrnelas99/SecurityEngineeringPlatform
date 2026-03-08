import { isTestIp } from "./threatControls.js";

// In-memory counters for login failure tracking and temporary lock windows.
const ipFailures = new Map();
const userFailures = new Map();
const ipLockUntil = new Map();
const userLockUntil = new Map();

// Backoff policy knobs (window, max failures, and exponential lock duration).
const WINDOW_MS = Number(process.env.LOGIN_FAILURE_WINDOW_MS || 10 * 60 * 1000);
const MAX_FAILURES = Number(process.env.LOGIN_MAX_FAILURES || 5);
const BASE_LOCK_MS = Number(process.env.LOGIN_BASE_LOCK_MS || 30 * 1000);
const MAX_LOCK_MS = Number(process.env.LOGIN_MAX_LOCK_MS || 15 * 60 * 1000);

// Normalize IPv6-mapped IPv4 addresses into standard IPv4 form.
function normalizeIp(ip) {
  const value = String(ip || "");
  return value.startsWith("::ffff:") ? value.slice(7) : value;
}

// Add a failed-attempt timestamp and keep only entries within active window.
function pushFailure(map, key, now) {
  const entries = map.get(key) || [];
  entries.push(now);
  const active = entries.filter((ts) => now - ts <= WINDOW_MS);
  map.set(key, active);
  return active.length;
}

// Clear failure history for a specific map key.
function clearFailures(map, key) {
  map.delete(key);
}

// Set lock expiration with exponential backoff once threshold is crossed.
function setLock(lockMap, key, count, now) {
  if (count < MAX_FAILURES) {
    return 0;
  }
  const overage = count - MAX_FAILURES;
  const lockMs = Math.min(BASE_LOCK_MS * Math.pow(2, overage), MAX_LOCK_MS);
  lockMap.set(key, now + lockMs);
  return lockMs;
}

// Return remaining lock duration in ms; clear expired locks.
function getRetryAfterMs(lockMap, key, now) {
  const until = lockMap.get(key) || 0;
  const remaining = until - now;
  if (remaining <= 0) {
    lockMap.delete(key);
    return 0;
  }
  return remaining;
}

// Read current lock state before attempting login.
export function getLoginProtectionState(req, usernameRaw = "") {
  const now = Date.now();
  const ip = normalizeIp(req.ip);
  const username = String(usernameRaw || "").trim().toLowerCase();
  if (isTestIp(ip)) {
    return { ip, username, retryAfterMs: 0, isTestIp: true };
  }
  const ipRetry = getRetryAfterMs(ipLockUntil, ip, now);
  const userRetry = username ? getRetryAfterMs(userLockUntil, username, now) : 0;
  const retryAfterMs = Math.max(ipRetry, userRetry);
  return { ip, username, retryAfterMs, isTestIp: false };
}

// Record one failed login attempt and update lock windows.
export function recordLoginFailure(req, usernameRaw = "") {
  const now = Date.now();
  const ip = normalizeIp(req.ip);
  const username = String(usernameRaw || "").trim().toLowerCase();
  if (isTestIp(ip)) {
    return {
      ip,
      username,
      ipCount: 0,
      userCount: 0,
      lockMs: 0,
      isTestIp: true
    };
  }

  const ipCount = pushFailure(ipFailures, ip, now);
  const userCount = username ? pushFailure(userFailures, username, now) : 0;

  const ipLockMs = setLock(ipLockUntil, ip, ipCount, now);
  const userLockMs = username ? setLock(userLockUntil, username, userCount, now) : 0;

  return {
    ip,
    username,
    ipCount,
    userCount,
    lockMs: Math.max(ipLockMs, userLockMs),
    isTestIp: false
  };
}

// Clear lock/failure state after successful authentication.
export function clearLoginProtection(req, usernameRaw = "") {
  const ip = normalizeIp(req.ip);
  const username = String(usernameRaw || "").trim().toLowerCase();
  clearFailures(ipFailures, ip);
  ipLockUntil.delete(ip);
  if (username) {
    clearFailures(userFailures, username);
    userLockUntil.delete(username);
  }
}
