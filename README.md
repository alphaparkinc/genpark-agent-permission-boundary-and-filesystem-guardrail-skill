# genpark-agent-permission-boundary-and-filesystem-guardrail-skill

Intercepts and audits autonomous agent tool execution against configurable security boundaries, protected paths, and destructive command filters.

100% Python Standard Library implementation with zero external dependencies.

## Key Capabilities
- **Workspace Confinement**: Enforces path normalization to prevent directory traversal escapes (`../`) outside designated project workspaces.
- **Sensitive Credential Shield**: Blocks write or destructive access to sensitive secret files (`.env`, `id_rsa`, `.git`, `.ssh`).
- **Destructive Shell Interception**: Scans shell command strings for high-risk system mutations (`rm -rf /`, `dd`, `mkfs`, fork bombs) and privilege escalations (`sudo`/`su`).
- **Zero Overhead**: Pure standard library execution with microsecond guardrail verification.

## Architecture

```
[Agent Tool Execution Request]
              │
              ▼
┌──────────────────────────────────────────────┐
│  AgentPermissionGuardrail                    │
│  ├─ Workspace Containment Path Auditor       │
│  ├─ Protected Secret Filter (.env, id_rsa)   │
│  └─ Destructive Regex Heuristic Scanner      │
└──────────────────────────────────────────────┘
              │
       ┌──────┴────────────────────────┐
       ▼                               ▼
[ALLOWED: Compliant]         [BLOCKED: Violation Notice]
```

## MCP Server Integration

Run standard MCP stdio server:
```bash
python mcp_server.py
```

Exposed Tools:
- `audit_path_access`: Verifies that file access respects workspace bounds and credential protection.
- `audit_command_safety`: Evaluates shell commands for destructive patterns and privilege escalation.

## Quickstart

```python
from client import AgentPermissionGuardrail

# Audit path access
res = AgentPermissionGuardrail.audit_path_access("/app/.env", "/app", allow_write=True)
print("Allowed:", res["allowed"])  # False

# Audit shell command
cmd_res = AgentPermissionGuardrail.audit_command_safety("sudo rm -rf /")
print("Safe:", cmd_res["safe"])  # False
```
