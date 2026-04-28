use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

const ALLOWED_COMMANDS: &[&str] = &[
    "engine_health",
    "run_local_demo_flow_no_network",
    "build_ai_planner_packet",
    "list_model_providers",
    "list_tool_capabilities",
    "build_attack_surface_graph_from_fixture",
    "map_vulnerability_intelligence_from_fixture",
];
const DENIED_TEXT: &[&str] = &[
    "run-portfolio-demo",
    "run-portfolio-operator-pipeline",
    "fetch-http-metadata",
    "fetch-and-analyze-headers",
];
const FORBIDDEN_KEYS: &[&str] = &[
    "api_key",
    "authorization",
    "cookie",
    "set-cookie",
    "bearer",
    "password",
    "secret",
    "argv",
    "args",
    "command",
    "shell",
    "executable",
    "module",
    "function",
];

#[derive(Debug, Deserialize)]
pub struct BridgeCommandRequest {
    pub command_name: String,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Serialize)]
pub struct BridgeCommandResult {
    pub command_name: String,
    pub status: String,
    pub data: Value,
    pub warnings: Vec<String>,
    pub errors: Vec<Value>,
    pub redaction_applied: bool,
    pub executed_live_network: bool,
    pub executed_external_tool: bool,
    pub metadata: Value,
}

#[tauri::command]
pub fn run_engine_bridge_command(request: BridgeCommandRequest) -> BridgeCommandResult {
    if !ALLOWED_COMMANDS.contains(&request.command_name.as_str()) {
        return denied(&request.command_name, "unsupported_bridge_command", "Bridge command is not allowlisted");
    }
    if let Some((code, message)) = validate_payload(&request.payload) {
        return denied(&request.command_name, code, message);
    }
    match call_python_bridge(&request.command_name, &request.payload) {
        Ok(value) => serde_json::from_value(value).unwrap_or_else(|_| {
            denied(
                &request.command_name,
                "invalid_bridge_response",
                "Python bridge returned an unexpected response shape",
            )
        }),
        Err(message) => denied(&request.command_name, "bridge_process_failed", &message),
    }
}

fn call_python_bridge(command_name: &str, payload: &Value) -> Result<Value, String> {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .and_then(|path| path.parent())
        .ok_or_else(|| "Could not resolve repository root".to_string())?;
    let engine_dir = repo_root.join("engine");
    let mut child = Command::new("python3")
        .arg("-m")
        .arg("aegis_ev.bridge")
        .arg("--command")
        .arg(command_name)
        .current_dir(engine_dir)
        .env("PYTHONPATH", "src")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Could not start Python bridge: {error}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        let body = serde_json::to_vec(payload).map_err(|error| format!("Could not serialize bridge payload: {error}"))?;
        stdin
            .write_all(&body)
            .map_err(|error| format!("Could not write bridge payload: {error}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|error| format!("Could not read Python bridge output: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if stdout.trim().is_empty() {
        return Err("Python bridge returned no JSON output".to_string());
    }
    serde_json::from_str(stdout.trim()).map_err(|error| format!("Python bridge JSON parse failed: {error}"))
}

fn validate_payload(value: &Value) -> Option<(&'static str, &'static str)> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let lowered = key.to_lowercase();
                if FORBIDDEN_KEYS.contains(&lowered.as_str()) {
                    return Some(("forbidden_payload_key", "Payload contains a forbidden key"));
                }
                if validate_payload(child).is_some() {
                    return validate_payload(child);
                }
            }
            None
        }
        Value::Array(items) => {
            for item in items {
                if validate_payload(item).is_some() {
                    return validate_payload(item);
                }
            }
            None
        }
        Value::String(text) => {
            let lowered = text.to_lowercase();
            let real_domain = ["alperenmanas", "app"].join(".");
            if lowered.contains(&real_domain) {
                return Some(("real_portfolio_url_denied", "Real portfolio URL is not accepted by the bridge stub"));
            }
            if DENIED_TEXT.iter().any(|blocked| lowered.contains(blocked)) {
                return Some(("live_command_reference_denied", "Payload references a command not allowed through the bridge"));
            }
            if lowered.contains("bearer ") || lowered.contains("sk-") {
                return Some(("token_like_payload_denied", "Payload contains token-like text"));
            }
            None
        }
        _ => None,
    }
}

fn denied(command_name: &str, code: &str, message: &str) -> BridgeCommandResult {
    BridgeCommandResult {
        command_name: command_name.to_string(),
        status: "denied".to_string(),
        data: json!({}),
        warnings: vec![],
        errors: vec![json!({ "code": code, "message": message })],
        redaction_applied: true,
        executed_live_network: false,
        executed_external_tool: false,
        metadata: json!({ "bridge_version": "tauri-python-bridge.v1", "allowed_no_network_only": true }),
    }
}
