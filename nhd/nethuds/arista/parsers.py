"""
Parsers for Arista EOS commands that don't support '| json' output.
Handles: show system environment all, show logging
"""

import re
from typing import Any


def parse_environment(raw: str) -> dict[str, Any]:
    """Parse 'show system environment all' text output."""
    result = {
        "sensors": [],
        "fans": [],
        "power_supplies": [],
        "ambient_temp": None,
        "airflow": None,
        "cooling_status": None,
        "temp_status": None,
    }

    # System status lines
    m = re.search(r"System temperature status is:\s*(\S+)", raw)
    if m:
        result["temp_status"] = m.group(1)

    m = re.search(r"System cooling status is:\s*(\S+)", raw)
    if m:
        result["cooling_status"] = m.group(1)

    m = re.search(r"Ambient temperature:\s*(\d+)C", raw)
    if m:
        result["ambient_temp"] = int(m.group(1))

    m = re.search(r"Airflow:\s*(.+)", raw)
    if m:
        result["airflow"] = m.group(1).strip()

    # ---- Temperature Sensors ----
    # Match lines like:
    # 1       Digital Temperature Sensor on cpu0     47.0   (80) 80.0     95       105
    # 26      STAT0 remote sensor                    80.1   (80) 80.0     95       100
    sensor_pat = re.compile(
        r"^\s*(\d+)\s+"           # sensor id
        r"(.+?)\s+"              # description (greedy but trailing spaces trimmed)
        r"(-?\d+\.?\d*)\s+"      # temp
        r"\(\d+\)\s+"            # setpoint in parens
        r"(-?\d+\.?\d*)\s+"      # setpoint value
        r"(-?\d+\.?\d*)\s+"      # alert limit
        r"(-?\d+\.?\d*)",        # critical limit
        re.MULTILINE,
    )

    # Track which PSU section we're in
    current_psu = None
    for line in raw.splitlines():
        psu_header = re.match(r"^PowerSupply\s+(\d+):", line)
        if psu_header:
            current_psu = int(psu_header.group(1))
            continue

        # Reset PSU context on non-PSU sections
        if re.match(r"^(System |Fan |Power )", line):
            current_psu = None

        sm = sensor_pat.match(line)
        if sm:
            sensor = {
                "id": int(sm.group(1)),
                "description": sm.group(2).strip(),
                "temp": float(sm.group(3)),
                "setpoint": float(sm.group(4)),
                "alert_limit": float(sm.group(5)),
                "critical_limit": float(sm.group(6)),
                "psu": current_psu,
            }
            result["sensors"].append(sensor)

    # ---- Fans ----
    # 1/1            Ok        32%    32% 541 days, 22:46:19 Stable    541 days, 22:46:00
    fan_pat = re.compile(
        r"^\s*([\w/]+)\s+"       # fan id
        r"(Ok|Not Inserted|Failed)\s+"  # status
        r"(\d+)%\s+"            # config speed
        r"(\d+)%\s+"            # actual speed
        r"([\d]+ days?,\s*[\d:]+)\s+"  # uptime
        r"(\w+)\s+"             # stability
        r"([\d]+ days?,\s*[\d:]+)",    # stable uptime
        re.MULTILINE,
    )
    for fm in fan_pat.finditer(raw):
        result["fans"].append({
            "id": fm.group(1),
            "status": fm.group(2),
            "config_speed": int(fm.group(3)),
            "actual_speed": int(fm.group(4)),
            "uptime": fm.group(5).strip(),
            "stability": fm.group(6),
            "stable_uptime": fm.group(7).strip(),
        })

    # ---- Power Supplies ----
    # 1      PWR-1900AC-F    1900W   2.83A  44.44A  539.0W Ok     531 days, 5:40:53
    psu_pat = re.compile(
        r"^\s*(\d+)\s+"              # supply number
        r"([\w-]+)\s+"               # model
        r"(\d+)W\s+"                 # capacity
        r"([\d.]+)A\s+"             # input current
        r"([\d.]+)A\s+"             # output current
        r"([\d.]+)W\s+"             # output power
        r"(Ok|Failed|Not Inserted)\s+"  # status
        r"([\d]+ days?,\s*[\d:]+)",    # uptime
        re.MULTILINE,
    )
    for pm in psu_pat.finditer(raw):
        result["power_supplies"].append({
            "id": int(pm.group(1)),
            "model": pm.group(2),
            "capacity_w": int(pm.group(3)),
            "input_amps": float(pm.group(4)),
            "output_amps": float(pm.group(5)),
            "output_watts": float(pm.group(6)),
            "status": pm.group(7),
            "uptime": pm.group(8).strip(),
        })

    return result


def parse_logging(raw: str) -> list[dict[str, Any]]:
    """Parse 'show logging last N' text output into structured entries.

    Anchors on the universal %FACILITY-SEVERITY-MNEMONIC: pattern present in
    every EOS syslog line, then parses the prefix for timestamp/host/source.

    Handles:
      - BSD:    Apr  4 02:01:07 host Agent: %FAC-5-MNEM: msg
      - ISO:    2026-03-04T00:17:44.678+00:00 host Agent: %FAC-5-MNEM: msg
    """
    entries = []

    for line in raw.splitlines():
        # Find the %FACILITY-SEVERITY-MNEMONIC: anchor
        m = re.search(r"%(\S+?)-(\d+)-(\S+?):\s*(.*)", line)
        if not m:
            continue

        facility = m.group(1)
        severity = int(m.group(2))
        mnemonic = m.group(3)
        message = m.group(4).strip()

        # Everything before the % is the prefix: timestamp, hostname, source
        prefix = line[: m.start()].strip()

        timestamp = ""
        host = ""
        source = ""

        # Try ISO8601: "2026-03-04T00:17:44.678096+00:00 host Agent:"
        ts_match = re.match(
            r"(\d{4}-\d{2}-\d{2}T[\d:.]+[+-][\d:]*)\s+(.*)", prefix
        )
        if not ts_match:
            # Try BSD/RFC3164: "Apr  4 02:01:07 host Agent:"
            ts_match = re.match(
                r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(.*)", prefix
            )
        if not ts_match:
            # Try with leading sequence number: "000023: Apr  4 02:01:07 host"
            ts_match = re.match(
                r"\d+:\s*(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(.*)", prefix
            )

        if ts_match:
            timestamp = ts_match.group(1).strip()
            remainder = ts_match.group(2).strip()
        else:
            remainder = prefix

        # Remainder is "hostname Source:" or "hostname"
        parts = remainder.split()
        if parts:
            host = parts[0]
            if len(parts) > 1:
                source = " ".join(parts[1:]).rstrip(":")

        entries.append({
            "timestamp": timestamp,
            "host": host,
            "source": source,
            "facility": facility,
            "severity": severity,
            "mnemonic": mnemonic,
            "message": message,
        })

    return entries