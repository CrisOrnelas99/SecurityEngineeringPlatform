// Runs the C++ crypto helper as a child process.
import { spawn } from "node:child_process";

// Path to crypto core binary injected by environment.
const coreBinary = process.env.SECURITY_CORE_BIN || "security_core";

// Public helper used by routes/services to call crypto-core operations.
// Sends JSON to stdin and expects JSON on stdout.
export function callCryptoCore(operation, payload) {
  // Execute the C++ binary operation and parse returned JSON.
  return new Promise((resolve, reject) => {
    const child = spawn(coreBinary, [operation], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => {
      stdout += data.toString("utf8");
    });

    child.stderr.on("data", (data) => {
      stderr += data.toString("utf8");
    });

    child.on("error", (error) => {
      reject(new Error(`Crypto core unavailable: ${error.message}`));
    });

    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`Crypto core returned ${code}: ${stderr}`));
        return;
      }

      try {
        resolve(JSON.parse(stdout));
      } catch {
        reject(new Error("Crypto core returned invalid JSON"));
      }
    });

    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}
