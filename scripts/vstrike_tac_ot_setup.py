#!/usr/bin/env python3
"""Prepare and smoke-test the TAC OT Water VStrike integration.

Run without a password to verify local defaults are staged. Run with
``--save-password`` after Aaron provides the password; the value is read with
getpass and stored through Vigil's secrets manager, not printed.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "backend"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))


DEFAULT_BASE_URL = "https://vstrike.net"
DEFAULT_USERNAME = "deeptempo_manager"
DEFAULT_WATER_NETWORK_ID = "69e5332fd395368a5f18f3f1"


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


def save_secret(key: str, value: str) -> None:
    from backend.secrets_manager import set_secret

    if not set_secret(key, value):
        raise SystemExit(f"Failed to save {key} via Vigil secrets manager")


def configured_value(key: str, default: str = "") -> str:
    from backend.secrets_manager import get_secret

    return get_secret(key) or os.environ.get(key) or default


def smoke(load_network: bool) -> None:
    from services.vstrike_service import get_vstrike_service

    svc = get_vstrike_service()
    if svc is None:
        raise SystemExit(
            "VStrike is not fully configured yet. Set VSTRIKE_PASSWORD after "
            "Aaron provides it, then rerun this script."
        )

    print("VStrike service: configured")
    print(f"Base URL: {svc.base_url}")
    print(f"Username: {svc.username}")

    tools = svc.list_tools()
    tool_names = sorted(t.get("name", "") for t in tools if isinstance(t, dict))
    required = {"ui-login-token", "network-list", "ui-network-load"}
    missing = sorted(required - set(tool_names))
    if missing:
        raise SystemExit(f"Missing expected VStrike MCP tools: {', '.join(missing)}")
    print("MCP tools: ui-login-token, network-list, ui-network-load present")

    token = svc.get_ui_login_token()
    if not token:
        raise SystemExit("ui-login-token returned no token")
    print("UI login token: ok")

    networks = svc.list_networks()
    print(f"Networks visible: {len(networks)}")
    for item in networks[:10]:
        if not isinstance(item, dict):
            continue
        network_id = (
            item.get("id")
            or item.get("networkId")
            or item.get("network_id")
            or item.get("identifier")
        )
        label = item.get("label") or item.get("name") or item.get("title") or network_id
        print(f"- {label} [{network_id}]")

    network_id = configured_value(
        "VSTRIKE_TAC_OT_WATER_NETWORK_ID", DEFAULT_WATER_NETWORK_ID
    )
    if load_network and network_id:
        result = svc.load_network_in_ui(network_id)
        print(f"Loaded TAC OT Water network: {network_id}")
        if isinstance(result, str):
            print(result)
        elif isinstance(result, dict):
            print(f"Load result keys: {', '.join(sorted(result.keys()))}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare and smoke-test TAC OT Water VStrike settings."
    )
    parser.add_argument(
        "--save-password",
        action="store_true",
        help="Prompt for Aaron's password and save it via Vigil secrets manager.",
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Call VStrike MCP login/tools and list visible networks.",
    )
    parser.add_argument(
        "--load-water-network",
        action="store_true",
        help="After smoke succeeds, call ui-network-load for the known TAC OT Water network.",
    )
    args = parser.parse_args()

    load_dotenv(ROOT / ".env")

    save_secret("VSTRIKE_BASE_URL", configured_value("VSTRIKE_BASE_URL", DEFAULT_BASE_URL))
    save_secret("VSTRIKE_VERIFY_SSL", configured_value("VSTRIKE_VERIFY_SSL", "true"))
    save_secret(
        "VSTRIKE_USERNAME", configured_value("VSTRIKE_USERNAME", DEFAULT_USERNAME)
    )
    save_secret(
        "VSTRIKE_TAC_OT_WATER_NETWORK_ID",
        configured_value("VSTRIKE_TAC_OT_WATER_NETWORK_ID", DEFAULT_WATER_NETWORK_ID),
    )

    print("Saved non-password VStrike TAC defaults.")

    if args.save_password:
        password = getpass.getpass("VStrike deeptempo_manager password: ")
        if not password:
            raise SystemExit("Password was empty; not saving.")
        save_secret("VSTRIKE_PASSWORD", password)
        print("Saved VSTRIKE_PASSWORD.")

    if args.smoke or args.load_water_network:
        smoke(load_network=args.load_water_network)
    else:
        if not configured_value("VSTRIKE_PASSWORD"):
            print("Ready for Aaron's password.")
            print(
                "Next: venv/bin/python scripts/vstrike_tac_ot_setup.py "
                "--save-password --smoke"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
