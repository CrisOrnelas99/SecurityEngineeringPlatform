import fs from "node:fs";
import path from "node:path";

const usersPath = path.join(process.cwd(), "data", "users.json");
const refreshTokenPath = path.join(process.cwd(), "data", "refreshTokens.json");

function readJson(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJson(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

export function getUsers() {
  return readJson(usersPath, []);
}

export function findUserByUsername(username) {
  return getUsers().find((u) => u.username === username);
}

export function findUserById(id) {
  return getUsers().find((u) => u.id === id);
}

export function saveUser(user) {
  const users = getUsers();
  users.push(user);
  writeJson(usersPath, users);
}

export function updateUser(updateUserData) {
  const users = getUsers();
  const idx = users.findIndex((u) => u.id === updateUserData.id);
  if (idx >= 0) {
    users[idx] = updateUserData;
    writeJson(usersPath, users);
  }
}

export function storeRefreshToken(record) {
  const tokens = readJson(refreshTokenPath, []);
  tokens.push(record);
  writeJson(refreshTokenPath, tokens);
}

export function revokeRefreshToken(token) {
  const tokens = readJson(refreshTokenPath, []);
  writeJson(refreshTokenPath, tokens.filter((t) => t.token !== token));
}

export function hasRefreshToken(token) {
  const tokens = readJson(refreshTokenPath, []);
  return tokens.some((t) => t.token === token);
}
