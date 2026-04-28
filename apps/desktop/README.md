# Aegis EV Desktop UI Shell

This is the first Tauri-compatible desktop UI shell for Aegis EV. It includes a safe bridge stub for a small set of no-network Python engine commands.

## Scope

- React and TypeScript UI scaffold.
- Tauri-compatible Rust shell configuration.
- Static mock data using `portfolio.example.test` and safe placeholder records.
- Allowlisted bridge commands for engine health, fixture-only demo summaries, AI packet building, model-provider metadata, tool capability metadata, fixture graph building, and fixture intelligence mapping.
- Mock fallback when the UI is not running inside Tauri.
- No live portfolio execution or live HTTP fetch from the UI.
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

This checks that mock UI data remains placeholder-only, that blocked live commands are not in the bridge allowlist, and that the Tauri config does not define broad sidecar execution.
