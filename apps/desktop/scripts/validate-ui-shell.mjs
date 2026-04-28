import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const files = [
  "src/mockData.ts",
  "src/App.tsx",
  "src/api/engineClient.ts",
  "src/api/types.ts",
  "src/components/EngineConnectionPanel.tsx",
  "src/styles.css",
  "src-tauri/tauri.conf.json",
  "src-tauri/src/main.rs",
  "src-tauri/src/engine_bridge.rs"
];

const realPortfolioDomain = ["alperenmanas", "app"].join(".");

const forbidden = [
  realPortfolioDomain,
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
  throw new Error("Tauri config must not define sidecar execution in TASK-025");
}

const bridge = readFileSync(join(root, "src-tauri/src/engine_bridge.rs"), "utf8");
for (const blockedCommand of ["run-portfolio-demo", "run-portfolio-operator-pipeline", "fetch-http-metadata", "fetch-and-analyze-headers"]) {
  const allowedList = bridge.match(/const ALLOWED_COMMANDS:[\s\S]*?\];/u)?.[0] ?? "";
  if (allowedList.includes(blockedCommand)) {
    throw new Error(`Bridge allowlist contains blocked command: ${blockedCommand}`);
  }
}
if (!bridge.includes(".arg(\"-m\")") || !bridge.includes(".arg(\"aegis_ev.bridge\")")) {
  throw new Error("Bridge must call the Python wrapper through fixed argv segments");
}
if (bridge.includes(".arg(command") && !bridge.includes("ALLOWED_COMMANDS.contains")) {
  throw new Error("Bridge command argument must be protected by an allowlist");
}

console.log("UI shell and bridge static validation passed.");
