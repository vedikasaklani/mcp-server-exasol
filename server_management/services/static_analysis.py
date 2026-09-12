'''Phase 1 building blocks: mechanical tool_declarations extraction (AST-only,
never executes target code), Semgrep SAST pattern scanning, and Semgrep
Supply Chain (SCA) dependency scanning. The manifest + manifest-history
commit lives in onboard_services.update_manifest, called by
record_rule_analysis_result - there is intentionally no commit path here.'''

import ast
import json
import os
import subprocess
import tempfile

_SKIP_DIRS = {".git", "venv", ".venv", "node_modules", "__pycache__", "dist", "build"}

# Tool declaration extraction

_TYPE_MAP = {
    "str": "string", "int": "integer", "float": "number",
    "bool": "boolean", "list": "array", "dict": "object",
}


def extract_tool_declarations(repo_path: str) -> list[dict]:
    """Walks every .py file under repo_path and mechanically extracts tool
    declarations exactly as written in source."""
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
                continue  
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


# Semgrep SAST scan

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
            "analyzer": "semgrep",
        })
    return findings


# Semgrep Supply Chain (SCA) scan

_SCA_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "LOW",
}


def run_semgrep_supply_chain_scan(repo_path: str) -> list[dict]:
    """Semgrep Supply Chain (SCA): scans the repo's manifest/lockfile
    against known-vulnerable and malicious open-source packages, with
    reachability analysis (whether the vulnerable function is actually
    called from this codebase, not just present as a dependency).
    """
    semgrep_bin = os.environ.get("SEMGREP_BIN", "semgrep")
    semgrep_app_token = os.environ.get("SEMGREP_APP_TOKEN")
    if not semgrep_app_token:
        raise RuntimeError(
            "SEMGREP_APP_TOKEN is required for Semgrep supply-chain scans"
        )

    fd, output_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        cmd = [
            semgrep_bin, "ci", "--supply-chain", "--dry-run",
            "--json-output", output_path,
            "--no-suppress-errors",
        ]
        env = os.environ.copy()
        env["SEMGREP_APP_TOKEN"] = semgrep_app_token
        timeout = int(os.environ.get("SEMGREP_SCA_TIMEOUT_SECONDS", "60"))
        try:
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"semgrep supply-chain scan timed out after {timeout} seconds"
            ) from exc

        if result.returncode != 0:
            raise RuntimeError(
                f"semgrep ci --supply-chain failed (exit {result.returncode}): "
                f"{result.stderr.strip()[-1500:]}"
            )
        with open(output_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    finally:
        try:
            os.remove(output_path)
        except OSError:
            pass

    findings = []
    for r in raw.get("results", []):
        extra = r.get("extra", {})
        metadata = extra.get("metadata", {})
        sca_info = extra.get("sca_info", {})
        dep = sca_info.get("dependency_match", {}).get("found_dependency", {})
        sca_severity = (metadata.get("sca-severity") or "").upper()
        findings.append({
            "rule_id": r.get("check_id"),
            "file": r.get("path"),
            "line": r.get("start", {}).get("line"),
            "message": extra.get("message"),
            "severity": _SCA_SEVERITY_MAP.get(sca_severity, "LOW"),
            "analyzer": "semgrep-sca",
            "cve": metadata.get("cve") or metadata.get("sca-vuln-database-identifier"),
            "package": dep.get("package"),
            "package_version": dep.get("version"),
            "ecosystem": dep.get("ecosystem"),
            "transitivity": dep.get("transitivity"),   # "direct" | "transitive"
            "reachable": sca_info.get("reachable"),      # bool
            "fix_versions": metadata.get("sca-fix-versions", []),
        })
    return findings