export function formatEventTime(isoTs) {
  const dt = new Date(isoTs);
  if (Number.isNaN(dt.getTime())) {
    return isoTs;
  }
  return dt.toLocaleString();
}

export function getIpDisplayInfo(rawIp) {
  const ip = String(rawIp || "");
  if (ip.startsWith("::ffff:")) {
    return { version: "IPv4", value: ip.replace("::ffff:", "") };
  }
  if (ip.includes(":")) {
    return { version: "IPv6", value: ip };
  }
  return { version: "IPv4", value: ip };
}

export function normalizeEventName(name) {
  if (name === "BRUTE_FORCE") {
    return "FAILED_LOGIN_BURST";
  }
  if (name === "BLACKLISTED_IP_ACCESS") {
    return "BLOCKED_IP_REQUEST";
  }
  if (name === "ADMIN_DELETE_USER") {
    return "Admin Delete User";
  }
  if (name === "ADMIN_RESET_USER_PASS") {
    return "Admin Reset User Pass";
  }
  return name;
}

export function normalizeActionName(name) {
  if (name === "BLACKLISTED_IP_ACCESS") {
    return "AUTO_BLOCK_IP_ACCESS";
  }
  if (name === "TEST_IP_NO_BLOCK") {
    return "TEST_IP_NO_BLOCK";
  }
  return name;
}

export function formatDetailValue(key, value) {
  if (value === null || value === undefined) {
    return "n/a";
  }
  if (typeof value === "string") {
    const keyLc = String(key || "").toLowerCase();
    const maybeIp = keyLc.includes("ip") || value.includes(":") || /^\d{1,3}(\.\d{1,3}){3}$/.test(value);
    if (maybeIp) {
      const info = getIpDisplayInfo(value);
      if (info.value) {
        return `${info.version}: ${info.value}`;
      }
    }
    return value;
  }
  return String(value);
}
