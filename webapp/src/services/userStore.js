import db from "./db.js";

// Normalize DB row shape into app-level user object.
function mapUserRow(row) {
  if (!row) {
    return null;
  }
  return {
    id: row.id,
    username: row.username,
    role: row.role,
    passwordHash: row.password_hash,
    createdAt: row.created_at
  };
}

// Return all users ordered by creation time.
export function getUsers() {
  const rows = db
    .prepare("SELECT id, username, role, password_hash, created_at FROM users ORDER BY datetime(created_at) ASC")
    .all();
  return rows.map(mapUserRow);
}

// Lookup user by username.
export function findUserByUsername(username) {
  const row = db
    .prepare("SELECT id, username, role, password_hash, created_at FROM users WHERE username = ? LIMIT 1")
    .get(String(username || ""));
  return mapUserRow(row);
}

// Lookup user by unique ID.
export function findUserById(id) {
  const row = db
    .prepare("SELECT id, username, role, password_hash, created_at FROM users WHERE id = ? LIMIT 1")
    .get(String(id || ""));
  return mapUserRow(row);
}

// Insert new user record.
export function saveUser(user) {
  db.prepare(
    "INSERT INTO users (id, username, role, password_hash, created_at) VALUES (?, ?, ?, ?, ?)"
  ).run(
    String(user.id),
    String(user.username),
    String(user.role),
    String(user.passwordHash),
    String(user.createdAt)
  );
}

// Update existing user record fields.
export function updateUser(updateUserData) {
  db.prepare(
    "UPDATE users SET username = ?, role = ?, password_hash = ?, created_at = ? WHERE id = ?"
  ).run(
    String(updateUserData.username),
    String(updateUserData.role),
    String(updateUserData.passwordHash),
    String(updateUserData.createdAt),
    String(updateUserData.id)
  );
}

// Delete user by ID and return whether a row was removed.
export function deleteUserById(userId) {
  const result = db.prepare("DELETE FROM users WHERE id = ?").run(String(userId || ""));
  return result.changes > 0;
}

// Store refresh token (replace if token already exists).
export function storeRefreshToken(record) {
  db.prepare(
    "INSERT OR REPLACE INTO refresh_tokens (token, user_id, created_at) VALUES (?, ?, ?)"
  ).run(String(record.token), String(record.userId), String(record.createdAt));
}

// Revoke one refresh token.
export function revokeRefreshToken(token) {
  db.prepare("DELETE FROM refresh_tokens WHERE token = ?").run(String(token || ""));
}

// Revoke all refresh tokens for a specific user.
export function revokeRefreshTokensForUser(userId) {
  db.prepare("DELETE FROM refresh_tokens WHERE user_id = ?").run(String(userId || ""));
}

// Check whether refresh token exists in store.
export function hasRefreshToken(token) {
  const row = db.prepare("SELECT 1 AS found FROM refresh_tokens WHERE token = ? LIMIT 1").get(String(token || ""));
  return Boolean(row?.found);
}
