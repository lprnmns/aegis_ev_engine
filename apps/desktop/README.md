# Aegis EV Desktop UI Shell

This is the first Tauri-compatible desktop UI shell for Aegis EV. It is a mock-only interface for the authorized exposure validation workbench.

## Scope

- React and TypeScript UI scaffold.
- Tauri-compatible Rust shell configuration.
- Static mock data using `portfolio.example.test` and safe placeholder records.
- No live Python sidecar execution.
- No scanner, crawler, fuzzer, external tool, or model provider execution.
- No API keys or provider config.

## Run Later

If Node, Rust, and Tauri dependencies are available:

```bash
cd apps/desktop
npm install
npm run dev
npm run tauri dev
```

The repository validation does not require installing frontend dependencies.

## Static Check

```bash
cd apps/desktop
npm run check:shell
```

This checks that mock UI data remains placeholder-only and that the Tauri config does not define sidecar execution.
