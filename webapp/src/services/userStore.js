import db from "./db.js";

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

export function getUsers() {
  const rows = db
    .prepare("SELECT id, username, role, password_hash, created_at FROM users ORDER BY datetime(created_at) ASC")
    .all();
  return rows.map(mapUserRow);
}

export function findUserByUsername(username) {
  const row = db
    .prepare("SELECT id, username, role, password_hash, created_at FROM users WHERE username = ? LIMIT 1")
    .get(String(username || ""));
  return mapUserRow(row);
}

export function findUserById(id) {
  const row = db
    .prepare("SELECT id, username, role, password_hash, created_at FROM users WHERE id = ? LIMIT 1")
    .get(String(id || ""));
  return mapUserRow(row);
}

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

export function storeRefreshToken(record) {
  db.prepare(
    "INSERT OR REPLACE INTO refresh_tokens (token, user_id, created_at) VALUES (?, ?, ?)"
  ).run(String(record.token), String(record.userId), String(record.createdAt));
}

export function revokeRefreshToken(token) {
  db.prepare("DELETE FROM refresh_tokens WHERE token = ?").run(String(token || ""));
}

export function hasRefreshToken(token) {
  const row = db.prepare("SELECT 1 AS found FROM refresh_tokens WHERE token = ? LIMIT 1").get(String(token || ""));
  return Boolean(row?.found);
}
