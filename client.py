"""Agent Permission Boundary & Filesystem Guardrail.
100% Python Standard Library.
"""

from typing import List, Dict, Any, Set
import os
import re


class AgentPermissionGuardrail:
    """Evaluates agent tool execution requests against permission boundaries,
    path access restrictions, and destructive shell command patterns."""

    DEFAULT_PROTECTED_FILES = {
        ".env", ".env.local", ".env.production",
        "id_rsa", "id_ed25519", "credentials",
        ".git", ".gitconfig", ".ssh"
    }

    DESTRUCTIVE_COMMAND_PATTERNS = [
        r"\brm\s+-[rf]{1,2}\s+[/~]",
        r"\bdd\s+if=",
        r"\bmkfs\.",
        r"\bchmod\s+-R\s+777\s+/",
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;",  # Fork bomb
        r">\s*/dev/sd[a-z]",
        r"\bdrop\s+database\b",
        r"\btruncate\s+table\b",
    ]

    @classmethod
    def audit_path_access(
        cls,
        target_path: str,
        workspace_root: str,
        allow_write: bool = False,
    ) -> Dict[str, Any]:
        """Validates that a path stays inside the workspace boundary and does not touch sensitive credentials."""
        norm_target = os.path.normpath(target_path)
        norm_root = os.path.normpath(workspace_root)

        # Check directory traversal escape
        try:
            rel_path = os.path.relpath(norm_target, norm_root)
            escapes_workspace = rel_path.startswith("..") or os.path.isabs(rel_path)
        except ValueError:
            escapes_workspace = True

        # Check protected filenames
        base_name = os.path.basename(norm_target)
        is_protected = (
            base_name in cls.DEFAULT_PROTECTED_FILES or
            any(p in norm_target.split(os.sep) for p in cls.DEFAULT_PROTECTED_FILES)
        )

        if escapes_workspace:
            return {
                "allowed": False,
                "reason": "DIRECTORY_TRAVERSAL_VIOLATION",
                "message": f"Target path '{target_path}' attempts to escape authorized workspace '{workspace_root}'.",
            }

        if is_protected and allow_write:
            return {
                "allowed": False,
                "reason": "PROTECTED_CREDENTIAL_WRITE_VIOLATION",
                "message": f"Modifications to protected file '{base_name}' are strictly forbidden.",
            }

        return {
            "allowed": True,
            "normalized_path": norm_target,
            "is_protected": is_protected,
            "message": "Path access complies with security boundary.",
        }

    @classmethod
    def audit_command_safety(cls, command_line: str) -> Dict[str, Any]:
        """Scans shell commands for destructive actions or privilege escalations."""
        cmd_clean = command_line.strip()

        for pattern in cls.DESTRUCTIVE_COMMAND_PATTERNS:
            if re.search(pattern, cmd_clean, re.IGNORECASE):
                return {
                    "safe": False,
                    "risk_level": "CRITICAL",
                    "reason": "DESTRUCTIVE_COMMAND_PATTERN_DETECTED",
                    "matched_pattern": pattern,
                    "message": f"Command contains potentially catastrophic system modification instruction.",
                }

        # Check for sudo / su
        if re.search(r"\b(sudo|su|doas)\b", cmd_clean):
            return {
                "safe": False,
                "risk_level": "HIGH",
                "reason": "PRIVILEGE_ESCALATION_BLOCKED",
                "message": "Privilege escalation (sudo/su) is not permitted inside autonomous agent sandbox.",
            }

        return {
            "safe": True,
            "risk_level": "LOW",
            "message": "Command satisfies execution guardrail checks.",
        }
