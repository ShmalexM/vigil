"""A runtime layout without a repository venv must still load usable commands."""

import json
import sys
from types import SimpleNamespace

from core.integrations.mcp.service import MCPService
from core.integrations.mcp.verify_catalog import check_catalog


def test_catalog_loads_without_a_project_virtualenv(tmp_path):
    (tmp_path / "mcp-config.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fixture": {"command": "python3", "args": ["-m", "fixture"]}
                }
            }
        )
    )
    assert check_catalog(tmp_path) == {
        "catalog_entries": 1,
        "missing_runtime_prerequisites": [],
    }
    service = MCPService(
        project_root=tmp_path,
        integration_bridge=SimpleNamespace(derive_remote_mcp_env=lambda: {}),
        detection_rules=SimpleNamespace(get_mcp_env_vars=lambda: {}),
    )
    assert service.servers["fixture"].command == sys.executable


def test_existing_project_virtualenv_remains_selected(tmp_path):
    venv_python = (
        tmp_path
        / "venv"
        / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    )
    venv_python.parent.mkdir(parents=True)
    venv_python.touch()
    (tmp_path / "mcp-config.json").write_text('{"mcpServers": {}}')
    service = MCPService(
        project_root=tmp_path,
        integration_bridge=SimpleNamespace(derive_remote_mcp_env=lambda: {}),
        detection_rules=SimpleNamespace(get_mcp_env_vars=lambda: {}),
    )
    assert service.python_exe == venv_python
