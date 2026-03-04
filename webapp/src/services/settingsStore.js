import db from "./db.js";

const KEY_NEW_USER_INITIAL_PASSWORD = "new_user_initial_password";

export function getNewUserInitialPassword() {
  const row = db.prepare("SELECT value FROM app_settings WHERE key = ? LIMIT 1").get(KEY_NEW_USER_INITIAL_PASSWORD);
  return row?.value || "pass12345678";
}

export function setNewUserInitialPassword(value) {
  db.prepare(
    "INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
  ).run(KEY_NEW_USER_INITIAL_PASSWORD, String(value));
}

