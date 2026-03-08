import express from "express";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import rateLimit from "express-rate-limit";
import { v4 as uuidv4 } from "uuid";
import { validateBody, loginSchema, adminCreateUserSchema, changePasswordSchema, setInitialPasswordSchema } from "../middleware/validation.js";
import { callCryptoCore } from "../services/cryptoCoreClient.js";
import {
  findUserById,
  findUserByUsername,
  getUsers,
  saveUser,
  storeRefreshToken,
  hasRefreshToken,
  revokeRefreshToken,
  revokeRefreshTokensForUser,
  updateUser,
  deleteUserById
} from "../services/userStore.js";
import { writeAuditLog } from "../utils/logger.js";
import { getLockedUsers, isLockedUser } from "../middleware/threatControls.js";
import { clearLoginProtection, getLoginProtectionState, recordLoginFailure } from "../middleware/loginProtection.js";
import { authenticateToken } from "../middleware/auth.js";
import { authorize } from "../middleware/rbac.js";
import { getNewUserInitialPassword, setNewUserInitialPassword } from "../services/settingsStore.js";

// Auth and admin user-management API routes.
const router = express.Router();
// Short token fingerprint for logging without storing full secret material.
const tokenFingerprint = (token) => crypto.createHash("sha256").update(token).digest("hex").slice(0, 16);

// Login throttling to reduce brute-force pressure.
const loginRateLimiter = rateLimit({
  windowMs: Number(process.env.LOGIN_RATE_LIMIT_WINDOW_MS || 60 * 1000),
  max: Number(process.env.LOGIN_RATE_LIMIT_MAX || 12),
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  handler: (req, res) => {
    writeAuditLog({ req, event: "LOGIN_RATE_LIMIT", success: false, errorType: "RateLimitExceeded" });
    res.status(429).json({ error: "Too many login attempts. Try again shortly." });
  }
});

// Refresh throttling to reduce token-abuse bursts.
const refreshRateLimiter = rateLimit({
  windowMs: Number(process.env.REFRESH_RATE_LIMIT_WINDOW_MS || 60 * 1000),
  max: Number(process.env.REFRESH_RATE_LIMIT_MAX || 30),
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    writeAuditLog({ req, event: "REFRESH_RATE_LIMIT", success: false, errorType: "RateLimitExceeded" });
    res.status(429).json({ error: "Too many token refresh requests." });
  }
});

// Issue signed access and refresh tokens for a user identity.
function createTokens(user) {
  const accessToken = jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: Number(process.env.JWT_ACCESS_TTL || 900) }
  );
  const refreshToken = jwt.sign(
    { sub: user.id, type: "refresh" },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: Number(process.env.JWT_REFRESH_TTL || 604800) }
  );
  return { accessToken, refreshToken };
}

// Admin-only user creation using configured initial password.
router.post("/register", authenticateToken, authorize("admin"), validateBody(adminCreateUserSchema), async (req, res) => {
  const { username, role } = req.body;
  const initialPassword = getNewUserInitialPassword();
  if (findUserByUsername(username)) {
    writeAuditLog({ req, event: "REGISTER_DENIED", success: false, errorType: "DuplicateUser" });
    res.status(409).json({ error: "User already exists" });
    return;
  }

  try {
    const hashResult = await callCryptoCore("hash-password", { password: initialPassword });
    const newUser = {
      id: uuidv4(),
      username,
      role,
      passwordHash: hashResult.hash,
      createdAt: new Date().toISOString()
    };
    saveUser(newUser);
    writeAuditLog({
      req,
      event: "REGISTER_SUCCESS",
      success: true,
      userId: req.user?.sub || null,
      metadata: {
        createdUserId: newUser.id,
        createdUsername: username,
        role,
        actorUsername: req.user?.username || null
      }
    });
    res.status(201).json({
      id: newUser.id,
      username,
      role,
      temporaryPassword: initialPassword
    });
  } catch (error) {
    if (String(error?.code || "") === "SQLITE_CONSTRAINT_UNIQUE") {
      writeAuditLog({ req, event: "REGISTER_DENIED", success: false, errorType: "DuplicateUser" });
      res.status(409).json({ error: "User already exists" });
      return;
    }
    writeAuditLog({ req, event: "REGISTER_FAIL", success: false, errorType: error.name, metadata: { reason: error.message } });
    res.status(500).json({ error: "Registration failed" });
  }
});

// Admin-only settings read endpoint.
router.get("/settings", authenticateToken, authorize("admin"), (req, res) => {
  const newUserInitialPassword = getNewUserInitialPassword();
  writeAuditLog({
    req,
    event: "SETTINGS_READ",
    success: true,
    userId: req.user?.sub || null
  });
  res.json({ newUserInitialPassword });
});

// Admin-only update for default new-user initial password.
router.post("/settings/new-user-password", authenticateToken, authorize("admin"), validateBody(setInitialPasswordSchema), (req, res) => {
  const { newUserInitialPassword } = req.body;
  setNewUserInitialPassword(newUserInitialPassword);
  writeAuditLog({
    req,
    event: "SETTINGS_UPDATE",
    success: true,
    userId: req.user?.sub || null,
    metadata: { key: "new_user_initial_password" }
  });
  res.json({ success: true, message: "Default new-user password updated." });
});

// Authenticate credentials, enforce login protection, then issue tokens.
router.post("/login", loginRateLimiter, validateBody(loginSchema), async (req, res) => {
  const { username, password } = req.body;
  const protection = getLoginProtectionState(req, username);
  if (protection.retryAfterMs > 0) {
    const retryAfterSeconds = Math.max(1, Math.ceil(protection.retryAfterMs / 1000));
    res.set("Retry-After", String(retryAfterSeconds));
    writeAuditLog({
      req,
      event: "LOGIN_THROTTLED",
      success: false,
      errorType: "BackoffActive",
      metadata: { username, retryAfterSeconds }
    });
    res.status(429).json({ error: "Too many failed login attempts. Try again later." });
    return;
  }

  const user = findUserByUsername(username);

  if (!user) {
    recordLoginFailure(req, username);
    writeAuditLog({ req, event: "LOGIN_FAIL", success: false, errorType: "UserNotFound", metadata: { username } });
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }
  if (isLockedUser(user.id) && user.role !== "admin") {
    writeAuditLog({ req, event: "LOGIN_FAIL", success: false, userId: user.id, errorType: "LockedUser" });
    res.status(423).json({ error: "Account locked" });
    return;
  }
  if (isLockedUser(user.id) && user.role === "admin") {
    writeAuditLog({ req, event: "LOCKED_USER_BYPASS_ADMIN", success: true, userId: user.id });
  }

  try {
    const verifyResult = await callCryptoCore("verify-password", { password, hash: user.passwordHash });
    if (!verifyResult.valid) {
      recordLoginFailure(req, username);
      writeAuditLog({ req, event: "LOGIN_FAIL", success: false, userId: user.id, errorType: "BadPassword" });
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    const { accessToken, refreshToken } = createTokens(user);
    storeRefreshToken({ token: refreshToken, userId: user.id, createdAt: new Date().toISOString() });
    clearLoginProtection(req, username);

    writeAuditLog({ req, event: "LOGIN_SUCCESS", success: true, userId: user.id, metadata: { role: user.role } });
    res.json({ accessToken, refreshToken, user: { id: user.id, username: user.username, role: user.role } });
  } catch (error) {
    writeAuditLog({ req, event: "LOGIN_FAIL", success: false, userId: user.id, errorType: error.name, metadata: { reason: error.message } });
    res.status(500).json({ error: "Login failed" });
  }
});

// Rotate refresh token and mint new access token pair.
router.post("/refresh", refreshRateLimiter, async (req, res) => {
  const refreshToken = req.body?.refreshToken;
  if (!refreshToken || !hasRefreshToken(refreshToken)) {
    writeAuditLog({
      req,
      event: "TOKEN_REFRESH_FAIL",
      success: false,
      errorType: "UnknownToken",
      metadata: { tokenFingerprint: refreshToken ? tokenFingerprint(refreshToken) : null }
    });
    res.status(401).json({ error: "Invalid refresh token" });
    return;
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const refreshedUser = findUserById(decoded.sub);
    const isAdmin = refreshedUser?.role === "admin";
    if (isLockedUser(decoded.sub) && !isAdmin) {
      writeAuditLog({ req, event: "TOKEN_REFRESH_FAIL", success: false, userId: decoded.sub, errorType: "LockedUser" });
      res.status(423).json({ error: "Account locked" });
      return;
    }
    if (isLockedUser(decoded.sub) && isAdmin) {
      writeAuditLog({ req, event: "LOCKED_USER_BYPASS_ADMIN", success: true, userId: decoded.sub });
    }
    const pseudoUser = {
      id: decoded.sub,
      username: refreshedUser?.username || "unknown",
      role: refreshedUser?.role || "analyst"
    };
    const { accessToken, refreshToken: newRefreshToken } = createTokens(pseudoUser);
    revokeRefreshToken(refreshToken);
    storeRefreshToken({ token: newRefreshToken, userId: decoded.sub, createdAt: new Date().toISOString() });

    writeAuditLog({
      req,
      event: "TOKEN_REFRESH_SUCCESS",
      success: true,
      userId: decoded.sub,
      metadata: { tokenFingerprint: tokenFingerprint(refreshToken) }
    });
    res.json({ accessToken, refreshToken: newRefreshToken });
  } catch (error) {
    writeAuditLog({ req, event: "TOKEN_REFRESH_FAIL", success: false, errorType: error.name });
    res.status(401).json({ error: "Expired or invalid refresh token" });
  }
});

// Return authenticated profile summary.
router.get("/me", authenticateToken, (req, res) => {
  const user = findUserById(req.user.sub);
  if (!user) {
    writeAuditLog({ req, event: "PROFILE_FAIL", success: false, userId: req.user.sub, errorType: "UserNotFound" });
    res.status(404).json({ error: "User not found" });
    return;
  }
  writeAuditLog({ req, event: "PROFILE_SUCCESS", success: true, userId: user.id });
  res.json({
    id: user.id,
    username: user.username,
    role: user.role,
    createdAt: user.createdAt
  });
});

// Authenticated self-service password change flow.
router.post("/change-password", authenticateToken, validateBody(changePasswordSchema), async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = findUserById(req.user.sub);
  if (!user) {
    writeAuditLog({ req, event: "PASSWORD_CHANGE_FAIL", success: false, userId: req.user.sub, errorType: "UserNotFound" });
    res.status(404).json({ error: "User not found" });
    return;
  }

  try {
    const currentCheck = await callCryptoCore("verify-password", { password: currentPassword, hash: user.passwordHash });
    if (!currentCheck.valid) {
      writeAuditLog({ req, event: "PASSWORD_CHANGE_FAIL", success: false, userId: user.id, errorType: "BadPassword" });
      res.status(401).json({ error: "Current password is incorrect" });
      return;
    }

    const hashResult = await callCryptoCore("hash-password", { password: newPassword });
    updateUser({ ...user, passwordHash: hashResult.hash });
    revokeRefreshTokensForUser(user.id);

    writeAuditLog({ req, event: "PASSWORD_CHANGE_SUCCESS", success: true, userId: user.id });
    res.json({ success: true, message: "Password updated. Please log in again." });
  } catch (error) {
    writeAuditLog({
      req,
      event: "PASSWORD_CHANGE_FAIL",
      success: false,
      userId: user.id,
      errorType: error.name,
      metadata: { reason: error.message }
    });
    res.status(500).json({ error: "Password update failed" });
  }
});

// Admin-only list users endpoint.
router.get("/users", authenticateToken, authorize("admin"), (req, res) => {
  const locked = getLockedUsers();
  const users = getUsers().map((user) => ({
    id: user.id,
    username: user.username,
    role: user.role,
    createdAt: user.createdAt,
    locked: locked.has(user.id)
  }));
  writeAuditLog({
    req,
    event: "USERS_LIST",
    success: true,
    userId: req.user?.sub || null,
    metadata: { count: users.length }
  });
  res.json(users);
});

// Admin-only reset-password endpoint for a target user.
router.post("/users/:id/reset-password", authenticateToken, authorize("admin"), async (req, res) => {
  const userId = String(req.params.id || "");
  const target = findUserById(userId);
  if (!target) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  try {
    const temporaryPassword = getNewUserInitialPassword();
    const hashResult = await callCryptoCore("hash-password", { password: temporaryPassword });
    updateUser({ ...target, passwordHash: hashResult.hash });
    revokeRefreshTokensForUser(target.id);
    writeAuditLog({
      req,
      event: "USER_PASSWORD_RESET",
      success: true,
      userId: req.user?.sub || null,
      metadata: { targetUserId: target.id, targetUsername: target.username }
    });
    res.json({ success: true, temporaryPassword });
  } catch (error) {
    writeAuditLog({
      req,
      event: "USER_PASSWORD_RESET_FAIL",
      success: false,
      userId: req.user?.sub || null,
      errorType: error.name,
      metadata: { targetUserId: target.id, reason: error.message }
    });
    res.status(500).json({ error: "Password reset failed" });
  }
});

// Admin-only delete user endpoint (cannot delete current session user).
router.delete("/users/:id", authenticateToken, authorize("admin"), (req, res) => {
  const userId = String(req.params.id || "");
  if (userId === req.user?.sub) {
    res.status(400).json({ error: "Cannot delete current user" });
    return;
  }
  const targetUser = findUserById(userId);
  if (!targetUser) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  const deleted = deleteUserById(userId);
  if (!deleted) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  writeAuditLog({
    req,
    event: "USER_DELETE",
    success: true,
    userId: req.user?.sub || null,
    metadata: {
      deletedUserId: userId,
      targetUsername: targetUser.username,
      actorUsername: req.user?.username || null
    }
  });
  res.json({ success: true, deletedUserId: userId });
});

// Logout revokes provided refresh token and ends session on client side.
router.post("/logout", (req, res) => {
  const refreshToken = req.body?.refreshToken;
  if (refreshToken) {
    revokeRefreshToken(refreshToken);
  }
  writeAuditLog({ req, event: "LOGOUT", success: true });
  res.status(204).send();
});

export default router;
