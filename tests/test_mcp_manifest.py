"""Hedef MCP tool-manifest statik taraması (#6). Ağsız, deterministik."""
from __future__ import annotations

from pentestai.detector import McpManifestScanner

SCANNER = McpManifestScanner()


def _scan(tools):
    return SCANNER.scan_manifest({"tools": tools})


def test_command_execution_tool_is_flagged_critical():
    f = _scan([{"name": "run_shell", "description": "execute a shell command",
                "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}}}])
    assert len(f) == 1
    assert f[0].type == "dangerous_mcp_tool" and f[0].severity == "Critical"
    assert f[0].parameter == "command_execution"
    assert f[0].cwe == "CWE-749" and f[0].mitre.startswith("T1059")


def test_benign_tools_are_not_flagged():
    f = _scan([{"name": "get_weather", "description": "returns weather for a city"},
               {"name": "list_docs", "description": "list available documents"}])
    assert f == []


def test_multiple_dangerous_tools_each_reported():
    f = _scan([
        {"name": "eval_python", "description": "evaluate python code"},
        {"name": "delete_file", "description": "remove a file from disk"},
        {"name": "http_fetch", "description": "download a URL"},
    ])
    kinds = {x.parameter for x in f}
    assert kinds == {"code_evaluation", "destructive_fs", "network_fetch"}
    sev = {x.parameter: x.severity for x in f}
    assert sev["code_evaluation"] == "Critical" and sev["network_fetch"] == "Medium"


def test_loose_schema_adds_marker():
    f = _scan([{"name": "run_command", "description": "runs a command"}])  # şema yok → gevşek
    assert any("şeması gevşek" in m for m in f[0].evidence.leaked_markers)


def test_strict_schema_no_loose_marker():
    f = _scan([{"name": "run_command", "description": "runs an allowed command",
                "inputSchema": {"type": "object", "additionalProperties": False,
                                "properties": {"cmd": {"type": "string", "enum": ["ls", "pwd"]}}}}])
    assert not any("şeması gevşek" in m for m in f[0].evidence.leaked_markers)


def test_verdict_is_likely_not_confirmed():
    """Statik sinyal → LIKELY (kanıtlanmış istismar değil); 'güvenli demeyiz' disiplini."""
    f = _scan([{"name": "exec", "description": "exec"}])
    assert f[0].verdict == "LIKELY"


def test_accepts_plain_list_and_ignores_garbage():
    assert SCANNER.scan_manifest([{"name": "shell_exec"}, "junk", None])[0].parameter == "command_execution"
    assert SCANNER.scan_manifest({"nope": 1}) == []
    assert SCANNER.scan_manifest(None) == []
