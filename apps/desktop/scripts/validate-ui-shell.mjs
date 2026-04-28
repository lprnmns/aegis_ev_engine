import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const files = [
  "src/mockData.ts",
  "src/App.tsx",
  "src/styles.css",
  "src-tauri/tauri.conf.json",
  "src-tauri/src/main.rs"
];

const forbidden = [
  "alperenmanas.app",
  "OPENAI_API_KEY",
  "GEMINI_API_KEY",
  "NVIDIA_API_KEY",
  "LITELLM",
  "shell payload",
  "reverse shell",
  "exploit payload",
  "metasploit",
  "rce proof",
  "dump credentials"
];

for (const file of files) {
  const content = readFileSync(join(root, file), "utf8");
  for (const needle of forbidden) {
    if (content.toLowerCase().includes(needle.toLowerCase())) {
      throw new Error(`${file} contains forbidden text: ${needle}`);
    }
  }
}

const mock = readFileSync(join(root, "src/mockData.ts"), "utf8");
if (!mock.includes("https://portfolio.example.test")) {
  throw new Error("mockData.ts must use placeholder portfolio target");
}
if (!mock.includes("status: \"candidate\"")) {
  throw new Error("mock findings must remain candidate-only");
}

const tauriConfig = JSON.parse(readFileSync(join(root, "src-tauri/tauri.conf.json"), "utf8"));
if (JSON.stringify(tauriConfig).toLowerCase().includes("sidecar")) {
  throw new Error("Tauri config must not define sidecar execution in TASK-024");
}

console.log("UI shell static validation passed.");
