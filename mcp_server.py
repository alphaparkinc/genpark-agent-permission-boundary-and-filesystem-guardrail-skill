"""MCP server for Agent Permission Boundary & Filesystem Guardrail."""
import sys
import json
from client import AgentPermissionGuardrail


def handle_request(req):
    method = req.get("method")
    if method == "tools/list":
        return {
            "tools": [
                {
                    "name": "audit_path_access",
                    "description": "Verifies that an agent file operation stays strictly within workspace boundaries and does not touch sensitive secrets",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "target_path": {"type": "string", "description": "Target file or directory path"},
                            "workspace_root": {"type": "string", "description": "Absolute root path of authorized workspace"},
                            "allow_write": {"type": "boolean", "default": False},
                        },
                        "required": ["target_path", "workspace_root"],
                    },
                },
                {
                    "name": "audit_command_safety",
                    "description": "Audits a terminal shell command string for catastrophic system deletion or privilege escalation",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command_line": {"type": "string", "description": "Command string about to be run"}
                        },
                        "required": ["command_line"],
                    },
                },
            ]
        }
    elif method == "tools/call":
        params = req.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})
        if tool_name == "audit_path_access":
            res = AgentPermissionGuardrail.audit_path_access(
                args.get("target_path", ""),
                args.get("workspace_root", ""),
                allow_write=args.get("allow_write", False),
            )
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
        elif tool_name == "audit_command_safety":
            res = AgentPermissionGuardrail.audit_command_safety(args.get("command_line", ""))
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
    return {"error": "Method not found"}


if __name__ == "__main__":
    for line in sys.stdin:
        if line.strip():
            print(json.dumps(handle_request(json.loads(line))))
            sys.stdout.flush()
