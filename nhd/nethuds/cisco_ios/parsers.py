"""
Parsers for Cisco IOS CLI output.
No JSON support — everything is regex-parsed text.
Covers: show version, show environment, show processes cpu,
        show interfaces status, show lldp neighbors, show ip route summary,
        show logging, show inventory, show spanning-tree summary,
        show mac address-table count
"""

import re
from typing import Any


def parse_version(raw: str) -> dict[str, Any]:
    """Parse 'show version' output."""
    result = {
        "hostname": "---",
        "model": "---",
        "serial": "---",
        "ios_version": "---",
        "uptime": "---",
        "mem_total": 0,
        "mem_used": 0,
        "image": "---",
        "reload_reason": "---",
    }

    m = re.search(r"^(\S+)\s+uptime is\s+(.+)$", raw, re.MULTILINE)
    if m:
        result["hostname"] = m.group(1)
        result["uptime"] = m.group(2).strip()

    m = re.search(r"Cisco IOS Software.*Version\s+([\S]+)", raw)
    if m:
        result["ios_version"] = m.group(1).rstrip(",")

    m = re.search(r'System image file is "(.+?)"', raw)
    if m:
        result["image"] = m.group(1)

    m = re.search(r"^cisco\s+(\S+)", raw, re.MULTILINE)
    if not m:
        m = re.search(r"^Cisco\s+(\S+)", raw, re.MULTILINE)
    if m:
        result["model"] = m.group(1)

    # Also try the "Model number" line
    m2 = re.search(r"Model [Nn]umber\s*:\s*(\S+)", raw)
    if m2:
        result["model"] = m2.group(1)

    m = re.search(r"System serial number\s*:\s*(\S+)", raw, re.IGNORECASE)
    if not m:
        m = re.search(r"Processor board ID\s+(\S+)", raw)
    if m:
        result["serial"] = m.group(1)

    # Memory: "cisco WS-C4948E (MPC8548) processor with 524288K bytes of physical memory."
    m = re.search(r"(\d+)K(?:/(\d+)K)? bytes of (?:physical )?memory", raw)
    if m:
        result["mem_total"] = int(m.group(1))
        if m.group(2):
            result["mem_used"] = int(m.group(1))
            result["mem_total"] = int(m.group(1)) + int(m.group(2))

    m = re.search(r"Last reload reason:\s*(.+)", raw)
    if not m:
        m = re.search(r"System returned to ROM by\s+(.+)", raw)
    if m:
        result["reload_reason"] = m.group(1).strip()

    return result


def parse_environment(raw: str) -> dict[str, Any]:
    """Parse 'show environment status' output."""
    result = {
        "power_supplies": [],
        "chassis_type": "---",
        "fan_status": "---",
        "bandwidth_util": "---",
    }

    # Power supplies
    # PS1     PWR-C49E-300AC-R  AC 300W    good         good     n.a.
    psu_pat = re.compile(
        r"^(PS\d+)\s+"
        r"([\w-]+)\s+"
        r"(AC|DC)\s+(\d+)W\s+"
        r"(\w+)\s+"           # status
        r"(\w[\w.]+)",        # fan sensor
        re.MULTILINE,
    )
    for m in psu_pat.finditer(raw):
        result["power_supplies"].append({
            "id": m.group(1),
            "model": m.group(2),
            "type": m.group(3),
            "watts": int(m.group(4)),
            "status": m.group(5),
            "fan": m.group(6),
        })

    m = re.search(r"Chassis Type\s*:\s*(\S+)", raw)
    if m:
        result["chassis_type"] = m.group(1)

    m = re.search(r"Fantray\s*:\s*(.+)", raw)
    if m:
        result["fan_status"] = m.group(1).strip()

    m = re.search(r"Switch Bandwidth Utilization\s*:\s*(.+)", raw)
    if m:
        result["bandwidth_util"] = m.group(1).strip()

    return result


def parse_temperature(raw: str) -> list[dict[str, Any]]:
    """Parse 'show environment temperature' output."""
    sensors = []
    # Various formats depending on platform
    # Inlet: 28C (Normal)  Hotpoint: 42C (Normal)
    temp_pat = re.compile(
        r"(\S+(?:\s+\S+)?)\s*:\s*(\d+)C\s*\((\w+)\)"
    )
    for m in temp_pat.finditer(raw):
        sensors.append({
            "name": m.group(1).strip(),
            "temp": int(m.group(2)),
            "status": m.group(3),
        })

    # Also handle tabular format:
    # Sensor       Temperature  Status  Threshold  Margin
    # Inlet         28 Celsius  Normal  56         28
    tab_pat = re.compile(
        r"^(\S+(?:\s+\S+)?)\s+(\d+)\s+Celsius\s+(\w+)\s+(\d+)\s+(\d+)",
        re.MULTILINE,
    )
    for m in tab_pat.finditer(raw):
        sensors.append({
            "name": m.group(1).strip(),
            "temp": int(m.group(2)),
            "status": m.group(3),
            "threshold": int(m.group(4)),
            "margin": int(m.group(5)),
        })

    return sensors


def parse_cpu(raw: str) -> dict[str, Any]:
    """Parse 'show processes cpu sorted' output."""
    result = {
        "five_sec": 0,
        "five_sec_interrupt": 0,
        "one_min": 0,
        "five_min": 0,
        "top_processes": [],
    }

    # CPU utilization for five seconds: 5%/0%; one minute: 5%; five minutes: 5%
    m = re.search(
        r"CPU utilization for five seconds:\s*(\d+)%/(\d+)%;\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%",
        raw,
    )
    if m:
        result["five_sec"] = int(m.group(1))
        result["five_sec_interrupt"] = int(m.group(2))
        result["one_min"] = int(m.group(3))
        result["five_min"] = int(m.group(4))

    # Parse top processes
    # PID Runtime(ms) Invoked uSecs 5Sec 1Min 5Min TTY Process
    proc_pat = re.compile(
        r"^\s*(\d+)\s+"          # PID
        r"(\d+)\s+"              # Runtime
        r"(\d+)\s+"              # Invoked
        r"(\d+)\s+"              # uSecs
        r"([\d.]+)%\s+"         # 5Sec
        r"([\d.]+)%\s+"         # 1Min
        r"([\d.]+)%\s+"         # 5Min
        r"(\d+)\s+"              # TTY
        r"(.+?)$",               # Process name
        re.MULTILINE,
    )
    for m in proc_pat.finditer(raw):
        cpu5 = float(m.group(5))
        if cpu5 > 0 or len(result["top_processes"]) < 10:
            result["top_processes"].append({
                "pid": int(m.group(1)),
                "runtime": int(m.group(2)),
                "invoked": int(m.group(3)),
                "five_sec": cpu5,
                "one_min": float(m.group(6)),
                "five_min": float(m.group(7)),
                "name": m.group(9).strip(),
            })
    result["top_processes"].sort(key=lambda p: p["five_sec"], reverse=True)
    result["top_processes"] = result["top_processes"][:10]

    return result


def parse_interfaces_status(raw: str) -> list[dict[str, Any]]:
    """Parse 'show interfaces status' output."""
    interfaces = []
    # Port      Name               Status       Vlan       Duplex  Speed Type
    # Gi1/1                        disabled     130          auto   auto 10/100/1000-TX
    intf_pat = re.compile(
        r"^((?:Gi|Te|Fa|Tw|Hu|Fo|Et)\S+)\s+"   # port
        r"(.*?)\s{2,}"                            # name (may be empty)
        r"(connected|notconnect|disabled|err-disabled|monitoring)\s+"  # status
        r"(\S+)\s+"                               # vlan
        r"(\S+)\s+"                               # duplex
        r"(\S+)\s+"                               # speed
        r"(.+?)$",                                # type
        re.MULTILINE,
    )
    for m in intf_pat.finditer(raw):
        interfaces.append({
            "port": m.group(1),
            "name": m.group(2).strip(),
            "status": m.group(3),
            "vlan": m.group(4),
            "duplex": m.group(5),
            "speed": m.group(6),
            "type": m.group(7).strip(),
        })

    return interfaces


def parse_interfaces_description(raw: str) -> list[dict[str, Any]]:
    """Parse 'show interfaces description' — works on IOS routers AND switches.

    Columns: Interface | Status (up/down/admin down) | Protocol (up/down) | Description
    'link' is True only when both line status and protocol are up.
    """
    rows: list[dict[str, Any]] = []
    pat = re.compile(
        r"^(?P<port>\S+)[ \t]+"
        r"(?P<status>admin down|up|down)[ \t]+"
        r"(?P<protocol>up|down)[ \t]*"
        r"(?P<desc>.*?)[ \t]*$",
        re.MULTILINE,
    )
    for m in pat.finditer(raw):
        status = m.group("status")
        proto = m.group("protocol")
        rows.append({
            "port": m.group("port"),
            "status": status,
            "protocol": proto,
            "description": m.group("desc").strip(),
            "link": status == "up" and proto == "up",
        })
    return rows


def parse_lldp(raw: str) -> list[dict[str, Any]]:
    """Parse 'show lldp neighbors' output."""
    neighbors = []
    # Device ID           Local Intf     Hold-time  Capability      Port ID
    # qfx                 Te1/50         120        B,R             xe-0/0/46
    lldp_pat = re.compile(
        r"^(\S+)\s+"               # Device ID
        r"((?:Gi|Te|Fa|Tw|Hu|Fo|Et)\S+)\s+"  # Local Intf
        r"(\d+)\s+"                # Hold-time
        r"([\w,]+)\s+"             # Capability
        r"(\S+)$",                 # Port ID
        re.MULTILINE,
    )
    for m in lldp_pat.finditer(raw):
        neighbors.append({
            "device": m.group(1),
            "local_intf": m.group(2),
            "holdtime": int(m.group(3)),
            "capability": m.group(4),
            "remote_port": m.group(5),
        })

    return neighbors


def parse_route_summary(raw: str) -> dict[str, Any]:
    """Parse 'show ip route summary' output."""
    result = {
        "table_name": "---",
        "routes": [],
        "total_networks": 0,
        "total_subnets": 0,
    }

    m = re.search(r"IP routing table name is (\S+)", raw)
    if m:
        result["table_name"] = m.group(1)

    # Route Source    Networks    Subnets     Overhead    Memory (bytes)
    # connected       0           1           64          152
    route_pat = re.compile(
        r"^(\w+)\s+"
        r"(\d+)\s+"        # Networks
        r"(\d+)\s+"        # Subnets
        r"(\d+)\s+"        # Overhead
        r"(\d+)",          # Memory
        re.MULTILINE,
    )
    for m in route_pat.finditer(raw):
        src = m.group(1)
        if src.lower() in ("route", "total"):
            if src.lower() == "total":
                result["total_networks"] = int(m.group(2))
                result["total_subnets"] = int(m.group(3))
            continue
        result["routes"].append({
            "source": src,
            "networks": int(m.group(2)),
            "subnets": int(m.group(3)),
            "memory": int(m.group(5)),
        })

    # Handle "internal" line which may not have subnets column
    m = re.search(r"^internal\s+(\d+)\s+(\d+)$", raw, re.MULTILINE)
    if m:
        result["routes"].append({
            "source": "internal",
            "networks": int(m.group(1)),
            "subnets": 0,
            "memory": int(m.group(2)),
        })

    # Total line
    m = re.search(r"^Total\s+(\d+)\s+(\d+)", raw, re.MULTILINE)
    if m:
        result["total_networks"] = int(m.group(1))
        result["total_subnets"] = int(m.group(2))

    return result


def parse_logging(raw: str) -> list[dict[str, Any]]:
    """Parse 'show logging' buffer output into structured entries."""
    entries = []
    # Mar 27 20:38:20.613: %SFF8472-5-THRESHOLD_VIOLATION: Te1/51: Tx power high warning
    log_pat = re.compile(
        r"^\*?(\w+\s+\d+\s+[\d:.]+):\s+"
        r"%(\S+?)-(\d)-(\S+?):\s+"
        r"(.+)$",
        re.MULTILINE,
    )
    for m in log_pat.finditer(raw):
        entries.append({
            "timestamp": m.group(1),
            "facility": m.group(2),
            "severity": int(m.group(3)),
            "mnemonic": m.group(4),
            "message": m.group(5).strip(),
        })

    return entries[-30:]  # Last 30 entries


def parse_inventory(raw: str) -> list[dict[str, Any]]:
    """Parse 'show inventory' output."""
    items = []
    # NAME: "TenGigabitEthernet1/49", DESCR: "SFP-10GBase-SR"
    # PID: SFP-10G-SR         , VID: V03  , SN: AVD2048E51L
    inv_pat = re.compile(
        r'NAME:\s*"(.+?)"\s*,\s*DESCR:\s*"(.+?)"\s*\n'
        r'PID:\s*(\S+)\s*,\s*VID:\s*(\S*)\s*,\s*SN:\s*(\S*)',
        re.MULTILINE,
    )
    for m in inv_pat.finditer(raw):
        items.append({
            "name": m.group(1),
            "description": m.group(2),
            "pid": m.group(3),
            "vid": m.group(4),
            "serial": m.group(5),
        })

    return items


def parse_spanning_tree_summary(raw: str) -> dict[str, Any]:
    """Parse 'show spanning-tree summary' — tabular AND prose formats."""
    result = {
        "mode": "---",
        "instances": 0,
        "root_bridges": 0,
        "blocking_ports": 0,
        "listening_ports": 0,
        "learning_ports": 0,
        "forwarding_ports": 0,
        "stp_active_ports": 0,
    }

    m = re.search(r"Switch is in (\S+)", raw)
    if m:
        result["mode"] = m.group(1)

    m = re.search(r"Root bridge for:\s*(.+)", raw)
    if m:
        vlans = m.group(1).strip()
        result["root_bridges"] = len(vlans.split(",")) if vlans and vlans.lower() != "none" else 0

    # Tabular totals row:  "4 vlans   4   0   0   6   10"
    #   N vlans  Blocking Listening Learning Forwarding STP-Active
    m = re.search(
        r"^\s*(\d+)\s+vlans?\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$",
        raw, re.IGNORECASE | re.MULTILINE,
    )
    if m:
        result["instances"]        = int(m.group(1))
        result["blocking_ports"]   = int(m.group(2))
        result["listening_ports"]  = int(m.group(3))
        result["learning_ports"]   = int(m.group(4))
        result["forwarding_ports"] = int(m.group(5))
        result["stp_active_ports"] = int(m.group(6))
        return result

    # Fallback: prose format (older / different IOS).
    m = re.search(r"(\d+)\s+interface.+blocking", raw, re.IGNORECASE)
    if m:
        result["blocking_ports"] = int(m.group(1))
    m = re.search(r"(\d+)\s+interface.+forwarding", raw, re.IGNORECASE)
    if m:
        result["forwarding_ports"] = int(m.group(1))
    m = re.search(r"(\d+)\s+vlans? currently", raw, re.IGNORECASE)
    if m:
        result["instances"] = int(m.group(1))

    return result


_MAC_ROW = re.compile(
    r"^\s*(?P<vlan>\d+|All|\*)\s+"
    r"(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<port>\S+)",
)


def parse_mac_table(raw: str) -> list[dict[str, Any]]:
    """Parse full 'show mac address-table' output into per-entry rows.

    Returns [] for the 'count' format (no per-entry rows present).
    """
    entries: list[dict[str, Any]] = []
    for line in raw.splitlines():
        m = _MAC_ROW.match(line)
        if not m:
            continue
        entries.append({
            "vlan": m.group("vlan"),
            "mac": m.group("mac").lower(),
            "type": m.group("type").lower(),
            "port": m.group("port"),
        })
    return entries


def parse_mac_count(raw: str) -> dict[str, Any]:
    """Parse MAC address-table summary, accepting BOTH output formats.

    * 'show mac address-table count'  -> reads Dynamic/Static/Total count lines
    * 'show mac address-table' (full) -> tallies counts from the Type column
    """
    result = {"total": 0, "static": 0, "dynamic": 0}

    # Fast path: native 'count' output. Count lines may repeat per-VLAN,
    # so sum every occurrence instead of taking only the first match.
    dyn = re.findall(r"Dynamic\s+Address\s+Count.*?:\s*(\d+)", raw, re.IGNORECASE)
    sta = re.findall(r"Static\s+Address\s+Count.*?:\s*(\d+)", raw, re.IGNORECASE)
    if dyn or sta:
        result["dynamic"] = sum(int(x) for x in dyn)
        result["static"] = sum(int(x) for x in sta)
        tot = re.findall(r"Total\s+Mac\s+Addresses.*?:\s*(\d+)", raw, re.IGNORECASE)
        result["total"] = sum(int(x) for x in tot) if tot else result["dynamic"] + result["static"]
        return result

    # Fallback: device returned the FULL table -> tally by Type column.
    entries = parse_mac_table(raw)
    if entries:
        for e in entries:
            if "dynamic" in e["type"]:
                result["dynamic"] += 1
            elif "static" in e["type"]:
                result["static"] += 1
        result["total"] = len(entries)
        return result

    # Last resort: only a 'Total ... criterion' line, no parseable rows.
    m = re.search(r"Total\s+Mac\s+Addresses.*?:\s*(\d+)", raw, re.IGNORECASE)
    if m:
        result["total"] = int(m.group(1))

    return result