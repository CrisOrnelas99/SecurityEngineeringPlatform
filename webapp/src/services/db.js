import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import Database from "better-sqlite3";

const dataDir = path.join(process.cwd(), "data");
const dbPath = process.env.WEBAPP_DB_PATH || path.join(dataDir, "security.db");
const usersJsonPath = path.join(dataDir, "users.json");
const refreshTokensJsonPath = path.join(dataDir, "refreshTokens.json");

fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const db = new Database(dbPath);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`);

function readJsonArray(filePath) {
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function hashPasswordScrypt(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `scrypt$${salt}$${derived}`;
}

function migrateFromJsonIfNeeded() {
  const userCount = db.prepare("SELECT COUNT(*) AS n FROM users").get().n;
  if (userCount === 0) {
    const users = readJsonArray(usersJsonPath);
    const insertUser = db.prepare(
      "INSERT OR IGNORE INTO users (id, username, role, password_hash, created_at) VALUES (?, ?, ?, ?, ?)"
    );
    const tx = db.transaction((items) => {
      for (const user of items) {
        insertUser.run(
          String(user.id || ""),
          String(user.username || ""),
          String(user.role || "analyst"),
          String(user.passwordHash || ""),
          String(user.createdAt || new Date().toISOString())
        );
      }
    });
    tx(users);
  }

  const tokenCount = db.prepare("SELECT COUNT(*) AS n FROM refresh_tokens").get().n;
  if (tokenCount === 0) {
    const tokens = readJsonArray(refreshTokensJsonPath);
    const insertToken = db.prepare(
      "INSERT OR IGNORE INTO refresh_tokens (token, user_id, created_at) VALUES (?, ?, ?)"
    );
    const tx = db.transaction((items) => {
      for (const token of items) {
        insertToken.run(
          String(token.token || ""),
          String(token.userId || ""),
          String(token.createdAt || new Date().toISOString())
        );
      }
    });
    tx(tokens);
  }
}

function ensureDefaultAdminUser() {
  const adminUsername = process.env.SOC_DEFAULT_ADMIN_USER || "admin";
  const adminPassword = process.env.SOC_DEFAULT_ADMIN_PASS || "pass12345678";
  const existing = db
    .prepare("SELECT id, password_hash FROM users WHERE username = ? LIMIT 1")
    .get(adminUsername);

  if (!existing) {
    db.prepare(
      "INSERT INTO users (id, username, role, password_hash, created_at) VALUES (?, ?, ?, ?, ?)"
    ).run(
      "admin-1",
      adminUsername,
      "admin",
      hashPasswordScrypt(adminPassword),
      new Date().toISOString()
    );
    return;
  }

  if (!existing.password_hash) {
    db.prepare("UPDATE users SET role = ?, password_hash = ? WHERE id = ?").run(
      "admin",
      hashPasswordScrypt(adminPassword),
      existing.id
    );
  }
}

function ensureDefaultAppSettings() {
  const defaultInitialPassword = process.env.NEW_USER_INITIAL_PASSWORD || "pass12345678";
  db.prepare("INSERT OR IGNORE INTO app_settings (key, value) VALUES (?, ?)").run(
    "new_user_initial_password",
    defaultInitialPassword
  );
}

migrateFromJsonIfNeeded();
ensureDefaultAdminUser();
ensureDefaultAppSettings();

export default db;
