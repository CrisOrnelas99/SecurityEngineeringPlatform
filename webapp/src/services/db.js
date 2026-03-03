import fs from "node:fs";
import path from "node:path";
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
`);

function readJsonArray(filePath) {
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
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

migrateFromJsonIfNeeded();

export default db;
