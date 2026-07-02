# TAC OT Water VStrike Setup

This runbook prepares Vigil for the TAC OT Water VStrike integration. The only
missing secret should be the `deeptempo_manager` password from Aaron.

## Current Defaults

Local `.env` is staged with:

```bash
VSTRIKE_BASE_URL="https://vstrike.net"
VSTRIKE_VERIFY_SSL="true"
VSTRIKE_USERNAME="deeptempo_manager"
VSTRIKE_PASSWORD=""
VSTRIKE_TAC_OT_WATER_NETWORK_ID="69e5332fd395368a5f18f3f1"
```

Do not commit or paste the password into docs. Save it through Vigil's secrets
manager when Aaron provides it.

## Save The Password

From the repo root:

```bash
venv/bin/python scripts/vstrike_tac_ot_setup.py --save-password --smoke
```

The script prompts for the password without echoing it, stores it through
`backend.secrets_manager.set_secret("VSTRIKE_PASSWORD", ...)`, and verifies:

- `/mcp-login` succeeds.
- `tools/list` exposes `ui-login-token`, `network-list`, and `ui-network-load`.
- `ui-login-token` returns a short-lived iframe login token.
- `network-list` returns visible networks.

To also push the known TAC OT Water network into the active VStrike UI session:

```bash
venv/bin/python scripts/vstrike_tac_ot_setup.py --smoke --load-water-network
```

## Vigil UI Check

1. Start Vigil normally.
2. Open an Investigation or the Dashboard entity graph.
3. The default entity graph should be replaced by the VStrike iframe once
   `VSTRIKE_USERNAME` and `VSTRIKE_PASSWORD` are configured.
4. Use the VStrike toolbar network selector to choose the TAC OT Water network.
5. If the selector is empty, rerun the smoke command and check the backend logs
   for `VStrike network-list failed`.

## Baseline PCAP Notes

The local baseline capture at `/Users/alexmargaris/Downloads/water.pcap` is
Modbus/TCP on port 502. Quick local parsing showed:

- Capture window: 2026-06-25 11:54:26 to 12:27:28.
- Packets: 116,943.
- HMI/client: `192.168.50.145`.
- PLC endpoints: `192.168.101.11:502`, `192.168.101.12:502`.
- Parsed Modbus ADUs: 23,388.
- Function codes: `3` read holding registers, `16` write multiple registers,
  `6` write single register.
- Unit ID: `1`.

Keep the demo claim narrow: this baseline supports Modbus-aware telemetry and
anomaly comparison. It is not, by itself, proof of vulnerability detection from
raw PCAP.
