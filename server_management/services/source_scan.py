"""A dependency-free static scanner for fetched MCP server sources.

The pipeline in scan_pipeline.py shells out to semgrep and a behavioural
LLM CLI. Both are worth having, and neither is always present: semgrep is a
large install with its own dependency tree, and the LLM CLI needs
credentials. A registry whose scan step only works on a fully provisioned
machine cannot gate admission on a fresh one, which is precisely where an
unknown server is most likely to be onboarded.

So this is the floor, not the ceiling: a small set of rules covering the
findings that actually disqualify an MCP server, implemented over the
standard library so the scan leg always runs. Where semgrep is available it
should still run and its findings merge with these.

Rules are deliberately conservative about severity. Everything here is
grep-shaped and cannot see reachability, so a finding says "this construct
is present", never "this is exploitable".
"""
from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# Directories that hold other people's code or build output. Scanning them
# reports thousands of findings about dependencies rather than about the
# server being onboarded, which buries the ones that matter.
_SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", "out", "coverage",
    "__pycache__", ".venv", "venv", ".next", ".cache", "vendor",
}
_SCAN_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".py", ".json"}
# Lockfiles are a machine-generated inventory of the registry, not source.
# Every rule that matches a URL or a long opaque string matches them
# hundreds of times, which buries the findings that are actually about this
# server.
_SKIP_FILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}
_MAX_FILE_BYTES = 2_000_000


@dataclass
class Rule:
    rule_id: str
    severity: str
    message: str
    pattern: re.Pattern[str]
    suffixes: frozenset[str] = field(default_factory=lambda: frozenset(_SCAN_SUFFIXES))


def _r(rule_id: str, severity: str, message: str, pattern: str, suffixes: Iterable[str] | None = None) -> Rule:
    return Rule(
        rule_id=rule_id,
        severity=severity,
        message=message,
        pattern=re.compile(pattern),
        suffixes=frozenset(suffixes) if suffixes else frozenset(_SCAN_SUFFIXES),
    )


RULES: tuple[Rule, ...] = (
    # Credentials committed to source. High confidence, high impact: these
    # are live secrets far more often than they are test fixtures.
    _r("secret.aws-access-key-id", "critical",
       "Hardcoded AWS access key id",
       r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _r("secret.aws-secret-key", "critical",
       "Hardcoded AWS secret access key",
       r"(?i)aws_?secret_?access_?key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]"),
    _r("secret.private-key", "critical",
       "Private key material committed to the repository",
       r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    _r("secret.github-token", "critical",
       "Hardcoded GitHub token",
       r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    _r("secret.slack-token", "critical",
       "Hardcoded Slack token",
       r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    _r("secret.generic-api-key", "high",
       "Hardcoded API key or password assignment",
       r"(?i)\b(?:api_?key|secret|passwd|password|token)\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{16,}['\"]"),

    # Arbitrary code and command execution.
    _r("exec.python-shell-true", "high",
       "subprocess invoked with shell=True",
       r"subprocess\.(?:run|call|check_output|check_call|Popen)\([^)]*shell\s*=\s*True", [".py"]),
    _r("exec.python-eval", "high",
       "eval() or exec() on a runtime value",
       r"(?<![\w.])(?:eval|exec)\s*\(", [".py"]),
    _r("exec.python-os-system", "high",
       "os.system() executes a shell command",
       r"os\.system\s*\(", [".py"]),
    _r("exec.node-child-process", "high",
       "child_process exec/spawn with a shell",
       r"(?:child_process|require\(['\"]child_process['\"]\))\s*\.?\s*(?:exec|execSync|spawnSync|spawn)\s*\(",
       [".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"]),
    _r("exec.node-eval", "high",
       "eval() or new Function() on a runtime value",
       r"(?<![\w.])(?:eval\s*\(|new\s+Function\s*\()",
       [".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"]),

    # Reads of credential stores the server has no business touching.
    _r("dataflow.credential-path", "high",
       "Reads a well-known credential file path",
       r"['\"](?:/etc/(?:shadow|passwd)|~?/\.ssh/[^'\"]+|~?/\.aws/credentials|~?/\.config/gcloud/[^'\"]*|~?/\.docker/config\.json|~?/\.npmrc|~?/\.netrc)['\"]"),
    _r("dataflow.env-dump", "medium",
       "Serialises the whole process environment",
       r"JSON\.stringify\s*\(\s*process\.env\s*\)|json\.dumps\s*\(\s*(?:dict\s*\()?\s*os\.environ"),

    # Undeclared egress.
    # Code only: a lockfile is a list of registry URLs, and reporting each
    # one buries every real finding under hundreds of rows about npm itself.
    _r("network.outbound-call", "medium",
       "Outbound network call in server source",
       r"(?:fetch|axios|request|urlopen|requests\.(?:get|post|put|delete)|https?\.request)\s*\(\s*['\"`]https?://(?!localhost|127\.0\.0\.1)[A-Za-z0-9.-]+",
       [".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".py"]),

    # Prompt-injection shaped content in tool metadata.
    _r("mcp.tool-description-injection", "high",
       "Instruction-shaped phrasing in tool metadata",
       r"(?i)ignore (?:all )?previous instructions|disregard (?:all )?(?:prior|previous)|do not tell the user|without telling the user"),
)


def _iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        if path.suffix.lower() not in _SCAN_SUFFIXES or path.name in _SKIP_FILES:
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def scan_source(root: str) -> list[dict[str, Any]]:
    """Every rule match under root, as rule_findings-shaped dicts."""
    base = Path(root)
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for path in _iter_files(base):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = path.relative_to(base).as_posix()
        suffix = path.suffix.lower()
        for rule in RULES:
            if suffix not in rule.suffixes:
                continue
            for match in rule.pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                key = (rule.rule_id, rel, line)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "rule_id": rule.rule_id,
                    "severity": rule.severity,
                    "message": rule.message,
                    "file_path": rel,
                    "line": line,
                    "analyzer": "warden-builtin",
                    # Never the matched text itself for a secret rule: that
                    # would copy the credential into the findings store,
                    # which is exactly the exposure being reported.
                    "evidence": "" if rule.rule_id.startswith("secret.")
                    else match.group(0)[:200],
                })
    findings.sort(key=lambda f: (f["file_path"], f["line"], f["rule_id"]))
    return findings


_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def verdict_for(findings: list[dict[str, Any]]) -> str:
    """Map findings onto a RuleVerdict value.

    Only committed credentials and private keys fail outright. Everything
    else passes with findings, because a grep-shaped rule cannot tell a
    dangerous construct from a legitimate one, and blocking on that would
    make the scan leg something operators route around.
    """
    for finding in findings:
        if finding["rule_id"].startswith("secret.") and finding["severity"] == "critical":
            return "fail"
    return "pass_with_findings" if findings else "pass"


def extract_tools(root: str) -> list[dict[str, Any]]:
    """Tool declarations the source advertises, best effort.

    Covers the three shapes MCP servers actually use: a Python decorator, a
    JS/TS array of tool objects, and a package's own declared manifest.
    """
    base = Path(root)
    tools: dict[str, dict[str, Any]] = {}
    for path in _iter_files(base):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if path.suffix.lower() == ".py":
            for tool in _tools_from_python(text):
                tools.setdefault(tool["name"], tool)
        elif path.suffix.lower() in {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"}:
            for tool in _tools_from_js(text):
                tools.setdefault(tool["name"], tool)
    return sorted(tools.values(), key=lambda t: t["name"])


def _tools_from_python(text: str) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorated = any(
            "tool" in ast.unparse(d).lower() for d in node.decorator_list
        )
        if not decorated:
            continue
        out.append({
            "name": node.name,
            "description": (ast.get_docstring(node) or "").strip(),
            "parameter_schema": {
                "type": "object",
                "properties": {
                    arg.arg: {"type": "string"}
                    for arg in node.args.args
                    if arg.arg not in {"self", "cls"}
                },
            },
        })
    return out


# A tool object literal: a name, then a description somewhere after it.
_JS_TOOL = re.compile(
    r"""name\s*:\s*['"`](?P<name>[A-Za-z0-9_.-]{1,64})['"`]"""
    r"""(?P<rest>(?:.|\n){0,400}?)"""
    r"""description\s*:\s*['"`](?P<description>(?:[^'"`\\]|\\.){0,400})['"`]""",
)


def _tools_from_js(text: str) -> list[dict[str, Any]]:
    out = []
    for match in _JS_TOOL.finditer(text):
        name = match.group("name")
        # Skip package.json-ish and server metadata blocks, which use the
        # same key names but are not tools.
        if name in {"node", "npm", "default"}:
            continue
        out.append({
            "name": name,
            "description": match.group("description").replace("\\n", " ").strip(),
            "parameter_schema": {"type": "object"},
        })
    return out


def scan_package_metadata(root: str) -> dict[str, Any]:
    """Declared name/version/dependency count, for the scan report header."""
    pkg = Path(root) / "package.json"
    if not pkg.is_file():
        return {}
    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {
        "name": data.get("name", ""),
        "version": data.get("version", ""),
        "dependencies": len(data.get("dependencies") or {}),
    }
