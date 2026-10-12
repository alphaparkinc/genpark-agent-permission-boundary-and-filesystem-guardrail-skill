"""Example usage for Agent Permission Boundary & Filesystem Guardrail."""
from client import AgentPermissionGuardrail

if __name__ == "__main__":
    workspace = "/app/workspace"

    # 1. Test directory traversal escape
    traversal_path = "/app/workspace/../../etc/passwd"
    res1 = AgentPermissionGuardrail.audit_path_access(traversal_path, workspace)
    print("Traversal Path Allowed:", res1["allowed"])
    print("Reason:", res1.get("reason"))

    # 2. Test protected credential write attempt
    env_path = "/app/workspace/.env"
    res2 = AgentPermissionGuardrail.audit_path_access(env_path, workspace, allow_write=True)
    print("\nProtected Write Allowed:", res2["allowed"])
    print("Reason:", res2.get("reason"))

    # 3. Test destructive command interception
    cmd_dangerous = "rm -rf / --no-preserve-root"
    res3 = AgentPermissionGuardrail.audit_command_safety(cmd_dangerous)
    print("\nDangerous Command Safe:", res3["safe"])
    print("Risk Level:", res3["risk_level"])
