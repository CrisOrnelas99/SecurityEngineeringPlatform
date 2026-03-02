import express from "express";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import { v4 as uuidv4 } from "uuid";
import { validateBody, loginSchema, registerSchema } from "../middleware/validation.js";
import { callCryptoCore } from "../services/cryptoCoreClient.js";
import {
  findUserByUsername,
  saveUser,
  storeRefreshToken,
  hasRefreshToken,
  revokeRefreshToken
} from "../services/userStore.js";
import { writeAuditLog } from "../utils/logger.js";
import { isLockedUser } from "../middleware/threatControls.js";

const router = express.Router();
const tokenFingerprint = (token) => crypto.createHash("sha256").update(token).digest("hex").slice(0, 16);

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

router.post("/register", validateBody(registerSchema), async (req, res) => {
  const { username, password, role } = req.body;
  if (findUserByUsername(username)) {
    writeAuditLog({ req, event: "REGISTER_DENIED", success: false, errorType: "DuplicateUser" });
    res.status(409).json({ error: "User already exists" });
    return;
  }

  try {
    const hashResult = await callCryptoCore("hash-password", { password });
    const newUser = {
      id: uuidv4(),
      username,
      role,
      passwordHash: hashResult.hash,
      createdAt: new Date().toISOString()
    };
    saveUser(newUser);
    writeAuditLog({ req, event: "REGISTER_SUCCESS", success: true, userId: newUser.id, metadata: { role } });
    res.status(201).json({ id: newUser.id, username, role });
  } catch (error) {
    writeAuditLog({ req, event: "REGISTER_FAIL", success: false, errorType: error.name, metadata: { reason: error.message } });
    res.status(500).json({ error: "Registration failed" });
  }
});

router.post("/login", validateBody(loginSchema), async (req, res) => {
  const { username, password } = req.body;
  const user = findUserByUsername(username);

  if (!user) {
    writeAuditLog({ req, event: "LOGIN_FAIL", success: false, errorType: "UserNotFound", metadata: { username } });
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }
  if (isLockedUser(user.id)) {
    writeAuditLog({ req, event: "LOGIN_FAIL", success: false, userId: user.id, errorType: "LockedUser" });
    res.status(423).json({ error: "Account locked" });
    return;
  }

  try {
    const verifyResult = await callCryptoCore("verify-password", { password, hash: user.passwordHash });
    if (!verifyResult.valid) {
      writeAuditLog({ req, event: "LOGIN_FAIL", success: false, userId: user.id, errorType: "BadPassword" });
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    const { accessToken, refreshToken } = createTokens(user);
    storeRefreshToken({ token: refreshToken, userId: user.id, createdAt: new Date().toISOString() });

    writeAuditLog({ req, event: "LOGIN_SUCCESS", success: true, userId: user.id, metadata: { role: user.role } });
    res.json({ accessToken, refreshToken, user: { id: user.id, username: user.username, role: user.role } });
  } catch (error) {
    writeAuditLog({ req, event: "LOGIN_FAIL", success: false, userId: user.id, errorType: error.name, metadata: { reason: error.message } });
    res.status(500).json({ error: "Login failed" });
  }
});

router.post("/refresh", async (req, res) => {
  const { refreshToken } = req.body;
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
    if (isLockedUser(decoded.sub)) {
      writeAuditLog({ req, event: "TOKEN_REFRESH_FAIL", success: false, userId: decoded.sub, errorType: "LockedUser" });
      res.status(423).json({ error: "Account locked" });
      return;
    }
    const pseudoUser = { id: decoded.sub, username: "unknown", role: "analyst" };
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

router.post("/logout", (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    revokeRefreshToken(refreshToken);
  }
  writeAuditLog({ req, event: "LOGOUT", success: true });
  res.status(204).send();
});

export default router;
