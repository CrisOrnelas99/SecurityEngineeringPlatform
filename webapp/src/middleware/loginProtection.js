const ipFailures = new Map();
const userFailures = new Map();
const ipLockUntil = new Map();
const userLockUntil = new Map();

const WINDOW_MS = Number(process.env.LOGIN_FAILURE_WINDOW_MS || 10 * 60 * 1000);
const MAX_FAILURES = Number(process.env.LOGIN_MAX_FAILURES || 5);
const BASE_LOCK_MS = Number(process.env.LOGIN_BASE_LOCK_MS || 30 * 1000);
const MAX_LOCK_MS = Number(process.env.LOGIN_MAX_LOCK_MS || 15 * 60 * 1000);

function normalizeIp(ip) {
  const value = String(ip || "");
  return value.startsWith("::ffff:") ? value.slice(7) : value;
}

function pushFailure(map, key, now) {
  const entries = map.get(key) || [];
  entries.push(now);
  const active = entries.filter((ts) => now - ts <= WINDOW_MS);
  map.set(key, active);
  return active.length;
}

function clearFailures(map, key) {
  map.delete(key);
}

function setLock(lockMap, key, count, now) {
  if (count < MAX_FAILURES) {
    return 0;
  }
  const overage = count - MAX_FAILURES;
  const lockMs = Math.min(BASE_LOCK_MS * Math.pow(2, overage), MAX_LOCK_MS);
  lockMap.set(key, now + lockMs);
  return lockMs;
}

function getRetryAfterMs(lockMap, key, now) {
  const until = lockMap.get(key) || 0;
  const remaining = until - now;
  if (remaining <= 0) {
    lockMap.delete(key);
    return 0;
  }
  return remaining;
}

export function getLoginProtectionState(req, usernameRaw = "") {
  const now = Date.now();
  const ip = normalizeIp(req.ip);
  const username = String(usernameRaw || "").trim().toLowerCase();
  const ipRetry = getRetryAfterMs(ipLockUntil, ip, now);
  const userRetry = username ? getRetryAfterMs(userLockUntil, username, now) : 0;
  const retryAfterMs = Math.max(ipRetry, userRetry);
  return { ip, username, retryAfterMs };
}

export function recordLoginFailure(req, usernameRaw = "") {
  const now = Date.now();
  const ip = normalizeIp(req.ip);
  const username = String(usernameRaw || "").trim().toLowerCase();

  const ipCount = pushFailure(ipFailures, ip, now);
  const userCount = username ? pushFailure(userFailures, username, now) : 0;

  const ipLockMs = setLock(ipLockUntil, ip, ipCount, now);
  const userLockMs = username ? setLock(userLockUntil, username, userCount, now) : 0;

  return {
    ip,
    username,
    ipCount,
    userCount,
    lockMs: Math.max(ipLockMs, userLockMs)
  };
}

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

