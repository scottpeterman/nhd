# Juniper HUD

Real-time network device telemetry dashboard for Juniper JUNOS routers/switches, rendered in a military HUD aesthetic.

## Architecture

```
┌──────────────────┐     SSH/Netmiko      ┌──────────────────┐
│  Juniper Router   │◄───────────────────►│    collector.py    │
│  (JUNOS CLI)      │  show x | display   │  (poll loop)      │
│                   │       json          │  + jval() helper   │
└──────────────────┘                      └────────┬───────────┘
                                                   │ dict
                                          ┌────────▼───────────┐
                                          │     server.py       │
                                          │  FastAPI + WS push  │
                                          └────────┬───────────┘
                                                   │ WebSocket (JSON)
                                          ┌────────▼───────────┐
                                          │  static/index.html  │
                                          │  HUD frontend       │
                                          │  (vanilla JS)       │
                                          └────────────────────┘
```

## Quick Start

```bash
cd juniper-hud
pip install -r requirements.txt
vi config.yaml    # set host, username, key_file
python server.py
# Open http://localhost:8471
```

## Config

```yaml
device:
  host: "border1"
  username: "speterman"
  device_type: "juniper_junos"
  use_keys: true
  key_file: "~/.ssh/id_rsa"
  timeout: 30
  session_timeout: 60

poll_interval: 15

server:
  host: "0.0.0.0"
  port: 8471
```

## Data Sources

All commands use `| display json` for structured output:

| Key | Command |
|-----|---------|
| version | `show version \| display json` |
| routing_engine | `show chassis routing-engine \| display json` |
| environment | `show chassis environment \| display json` |
| hardware | `show chassis hardware \| display json` |
| bgp | `show bgp summary \| display json` |
| ospf | `show ospf neighbor \| display json` |
| lldp | `show lldp neighbors \| display json` |
| routes | `show route summary \| display json` |
| interfaces | `show interfaces terse \| display json` |
| optics | `show interfaces diagnostics optics \| display json` |
| alarms | `show system alarm \| display json` |
| logging | `show log messages \| last 30` (text parsed) |

## Juniper JSON Format

Juniper wraps every value in arrays: `[{"data": "value", "attributes": {...}}]`

The `jval()` helper (in both Python collector and JS frontend) flattens these:
```python
from collector import jval
hostname = jval(data["host-name"])  # "edge5-01" instead of [{"data": "edge5-01"}]
temp_c = jattr(data["temperature"], "junos:celsius")  # "31" from attributes
```

## HUD Panels

- **Routing Engines** — Per-RE CPU/memory gauges, temperature, load averages, mastership state
- **Thermal Matrix** — Heatmap of all chassis sensors (CB, FPC, PEM), grouped by subsystem
- **Optics Diagnostics** — Per-port module temperature, voltage, alarm status
- **System Alarms** — Active alarms with class and description
- **LLDP Topology** — Radar visualization of neighbors
- **Routing Tables** — Per-table route counts, protocol breakdown (inet.0, inet6.0, etc.)
- **OSPF Adjacencies** — Neighbor state, interface, area
- **BGP Peering Table** — Per-peer state, prefix counts, message counters, RIB summaries
- **Event Log** — Filterable syslog feed (ALL / WARN+ / CONFIG)
- **Active Interfaces** — Connected ports with speed and admin/oper status

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | HUD frontend |
| `WS /ws` | WebSocket telemetry feed |
| `GET /api/data` | REST fallback, current device state |
| `GET /api/status` | Server health check |

## Key Differences from Arista HUD

| Aspect | Arista | Juniper |
|--------|--------|---------|
| JSON format | Native flat JSON | Nested `[{"data":"..."}]` arrays |
| Environment | Text parsed (regex) | Native JSON via `\| display json` |
| CPU/Memory | `show processes top once` | `show chassis routing-engine` |
| Dual RE | N/A (single supervisor) | Full dual-RE support |
| Optics | Inventory-based | Per-port diagnostics with DOM |
| Alarms | Derived from sensors | Native `show system alarm` |
| Port | 8470 | 8471 |

## Extending

### Adding commands

1. Add to `COMMANDS` or `TEXT_COMMANDS` in `collector.py`
2. Add extraction function in `index.html` (e.g., `extractNewData()`)
3. Add rendering in the `render()` function

### Multiple devices

Same pattern as Arista HUD — config becomes a list, collector spawns per-device, WebSocket includes device ID.

## Requirements

- Python 3.10+
- Juniper JUNOS with SSH enabled
- SSH key-based auth configured
- `| display json` support (JUNOS 14.1+)