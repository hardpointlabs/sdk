import { init } from "./commands/init.js";

const args = process.argv.slice(2);
const command = args[0];

async function main() {
  if (command === "init") {
    await init();
  } else {
    console.error(`Unknown command: ${command}`);
    console.error("Available commands: init");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
