import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import Database from "better-sqlite3";

// Storage paths and security-core binary location.
const dataDir = path.join(process.cwd(), "data");
const dbPath = process.env.WEBAPP_DB_PATH || path.join(dataDir, "security.db");
const usersJsonPath = path.join(dataDir, "users.json");
const refreshTokensJsonPath = path.join(dataDir, "refreshTokens.json");
const securityCoreBin = process.env.SECURITY_CORE_BIN || "security_core";

fs.mkdirSync(path.dirname(dbPath), { recursive: true });

// SQLite initialization with WAL and FK enforcement.
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

// Read array-like JSON migration source files safely.
function readJsonArray(filePath) {
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

// One-time password hash generation through security_core binary.
function hashPasswordWithCore(password) {
  const proc = spawnSync(securityCoreBin, ["hash-password"], {
    input: JSON.stringify({ password }),
    encoding: "utf8"
  });
  if (proc.status !== 0) {
    throw new Error(`security_core hash-password failed: ${String(proc.stderr || "").trim()}`);
  }
  const payload = JSON.parse(String(proc.stdout || "{}"));
  if (!payload?.success || typeof payload.hash !== "string" || !payload.hash.length) {
    throw new Error("security_core returned invalid hash payload");
  }
  return payload.hash;
}

// Migrate legacy JSON users/tokens into SQLite when tables are empty.
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

// Ensure default admin account exists with hashed password.
function ensureDefaultAdminUser() {
  const adminUsername = process.env.TDR_DEFAULT_ADMIN_USER || "admin";
  const adminPassword = process.env.TDR_DEFAULT_ADMIN_PASS || "pass12345678";
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
      hashPasswordWithCore(adminPassword),
      new Date().toISOString()
    );
    return;
  }

  if (!existing.password_hash) {
    db.prepare("UPDATE users SET role = ?, password_hash = ? WHERE id = ?").run(
      "admin",
      hashPasswordWithCore(adminPassword),
      existing.id
    );
  }
}

// Ensure app settings table has default new-user password key.
function ensureDefaultAppSettings() {
  const defaultInitialPassword = process.env.NEW_USER_INITIAL_PASSWORD || "pass12345678";
  db.prepare("INSERT OR IGNORE INTO app_settings (key, value) VALUES (?, ?)").run(
    "new_user_initial_password",
    defaultInitialPassword
  );
}

// Startup initialization sequence.
migrateFromJsonIfNeeded();
ensureDefaultAdminUser();
ensureDefaultAppSettings();

export default db;
