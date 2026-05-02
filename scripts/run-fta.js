import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

const platform = os.platform();
const arch = os.arch();

let binaryDir;
if (platform === "darwin") {
  binaryDir = arch === "arm64" ? "fta-aarch64-apple-darwin" : "fta-x86_64-apple-darwin";
} else if (platform === "linux") {
  binaryDir = arch === "arm64" ? "fta-aarch64-unknown-linux-musl" : "fta-x86_64-unknown-linux-musl";
} else if (platform === "win32") {
  binaryDir = arch === "arm64" ? "fta-aarch64-pc-windows-msvc" : "fta-x86_64-pc-windows-msvc";
} else {
  console.error(`Unsupported platform: ${platform} ${arch}`);
  process.exit(1);
}

const binaryPath = path.join(
  process.cwd(),
  "node_modules",
  "fta-cli",
  "binaries",
  binaryDir,
  "fta"
);

if (!fs.existsSync(binaryPath)) {
  console.error(`FTA binary not found: ${binaryPath}`);
  process.exit(1);
}

const args = process.argv.slice(2);

const result = spawnSync(binaryPath, args, { stdio: "inherit" });

if (result.status !== null) {
  process.exit(result.status);
} else if (result.error) {
  throw result.error;
}
