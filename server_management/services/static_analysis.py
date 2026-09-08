'''Phase 1 building blocks: mechanical tool_declarations extraction (AST-only,
never executes target code), Semgrep pattern scanning, and the manifest +
manifest-history commit that must happen on every scan per the schema.'''

import ast
import json
import os
import subprocess

from sqlalchemy.orm import Session

from server_management.database.db_models import ServerManifest, ManifestHistory

_SKIP_DIRS = {".git", "venv", ".venv", "node_modules", "__pycache__", "dist", "build"}

# Tool declaration extraction


_TYPE_MAP = {
    "str": "string", "int": "integer", "float": "number",
    "bool": "boolean", "list": "array", "dict": "object",
}


def extract_tool_declarations(repo_path: str) -> list[dict]:
    """Walks every .py file under repo_path and mechanically extracts tool
    declarations exactly as written in source. Uses ast.parse only - never
    imports or executes the target code, since this runs before any
    sandboxing and the code may be malicious."""
    declarations = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for filename in files:
            if not filename.endswith(".py"):
                continue
            filepath = os.path.join(root, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    tree = ast.parse(f.read(), filename=filepath)
            except (SyntaxError, UnicodeDecodeError):
                continue  # unparsable file
            declarations.extend(_extract_from_tree(tree))
    return declarations


def _extract_from_tree(tree: ast.AST) -> list[dict]:
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            func = call.func if call else decorator
            if isinstance(func, ast.Attribute) and func.attr == "tool":
                found.append(_build_declaration(node, call))
    return found


def _build_declaration(node, call: ast.Call | None) -> dict:
    kwargs = {}
    if call is not None:
        for kw in call.keywords:
            if kw.arg and isinstance(kw.value, ast.Constant):
                kwargs[kw.arg] = kw.value.value

    name = kwargs.get("name", node.name)
    description = kwargs.get("description") or ast.get_docstring(node) or ""
    return {
        "name": name,
        "description": description,
        "parameter_schema": _schema_from_signature(node),
    }


def _schema_from_signature(node) -> dict:
    properties, required = {}, []
    args = node.args
    defaults_offset = len(args.args) - len(args.defaults)

    for i, arg in enumerate(args.args):
        if arg.arg == "self":
            continue
        json_type = "string"
        if arg.annotation is not None:
            json_type = _TYPE_MAP.get(_annotation_name(arg.annotation), "string")
        properties[arg.arg] = {"type": json_type}
        if i < defaults_offset:
            required.append(arg.arg)

    return {"type": "object", "properties": properties, "required": required}


def _annotation_name(annotation) -> str:
    if isinstance(annotation, ast.Name):
        return annotation.id
    if isinstance(annotation, ast.Subscript):  # e.g. List[str], Optional[int]
        return _annotation_name(annotation.value)
    if isinstance(annotation, ast.Attribute):
        return annotation.attr
    return "str"


# Semgrep scan

def run_semgrep_scan(repo_path: str) -> list[dict]:
    """Runs Semgrep's community security rulesets (deterministic, no API
    key) plus your own custom MCP rules if present at
    static_analysis_rules/mcp-rules.yaml alongside this file."""
    configs = ["p/security-audit", "p/secrets"]
    custom_rules = os.path.join(os.path.dirname(__file__), "static_analysis_rules", "mcp-rules.yaml")
    if os.path.exists(custom_rules):
        configs.append(custom_rules)

    # semgrep lives in its own isolated venv (see Dockerfile) because it
    # pins a different "mcp" version than the app's fastmcp-slim dependency.
    semgrep_bin = os.environ.get("SEMGREP_BIN", "semgrep")
    cmd = [semgrep_bin, "scan", "--json", "--quiet"]
    for cfg in configs:
        cmd += ["--config", cfg]
    cmd.append(repo_path)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode not in (0, 1):  # 1 = findings present, not a crash
        raise RuntimeError(f"semgrep failed: {result.stderr}")

    severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    findings = []
    for r in json.loads(result.stdout).get("results", []):
        findings.append({
            "rule_id": r.get("check_id"),
            "file": r.get("path"),
            "line": r.get("start", {}).get("line"),
            "message": r.get("extra", {}).get("message"),
            "severity": severity_map.get(r.get("extra", {}).get("severity"), "LOW"),
        })
    return findings


# Manifest + manifest-history commit

def commit_tool_declarations(db: Session, server_id: str, tool_declarations: list[dict],
                              change_reason: str = "static_analysis") -> None:
    """Writes freshly-extracted tool_declarations to the current-state
    manifest (bumping its version) and appends a matching row to
    ManifestHistory. allowed_destinations is untouched here - it stays
    operator-declared and is only ever changed via the manifest-edit flow."""
    manifest = db.get(ServerManifest, server_id)
    if manifest is None:
        raise ValueError(f"no manifest found for server_id={server_id}")

    new_version = manifest.version + 1
    manifest.tool_declarations = tool_declarations
    manifest.version = new_version  # updated_at bumps automatically (onupdate=func.now())

    db.add(ManifestHistory(
        server_id=server_id,
        version=new_version,
        allowed_destinations=manifest.allowed_destinations,
        tool_declarations=tool_declarations,
        change_reason=change_reason,
    ))
    db.commit()