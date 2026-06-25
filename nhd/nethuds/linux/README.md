# Linux HUD — Distro-Aware Collector Rewrite

Architectural redesign of the Linux HUD collector. The original collector treated every Linux host the same — it ran every command (`lldpctl`, `vtysh`, `sensors`, `systemctl`, `docker`) and silently ate failures. The rewrite probes the host once on first connect, builds a capability fingerprint, and only runs collectors whose gates are satisfied. The frontend adapts its panel layout based on the capabilities reported in each telemetry push.

This also aligns the Linux collector with the persistent-session architecture used by the Arista, Juniper, and Cisco HUDs. The original Linux collector connected and disconnected on every poll cycle. The new collector holds a single Netmiko session across cycles, reconnects on failure, and re-probes after reconnect.

---

## What Changed

### Before

```
__init__  →  collect()  →  _connect_ssh()  →  run all 11 methods  →  disconnect()
                ↑                                                          │
                └──────────────── next poll ────────────────────────────────┘
```

Every poll: connect, authenticate, run everything, disconnect. 2-4 seconds of SSH key exchange overhead per cycle. `_collect_lldp()` runs even on hosts without lldpd. `_collect_frr()` runs `vtysh` on Ubuntu desktops. Empty data comes back, frontend renders blank panels.

### After

```
__init__  →  _ensure_connected()  →  _probe()  →  collect()  →  collect()  →  ...
                    ↑                  (once)        (gated)      (gated)
                    └──── reconnect if session drops, re-probe ────┘
```

Connect once. Probe once. Hold the session. Run only what the host supports. Reconnect and re-probe automatically on session death.

---

## Phases

### Phase 1 — Collector Refactor ✅

**Status: Complete**

The `collector.py` rewrite delivers three things:

**1. Persistent session management** — mirrors the Arista `_ensure_connected()` pattern exactly. The `_conn` is a Netmiko `ConnectHandler` held across poll cycles. On each cycle, `_ensure_connected()` checks `is_alive()` and reconnects only if the session has dropped. Prompt regex is captured once and cached for the session lifetime.

Local mode (localhost/127.0.0.1/::1) bypasses SSH entirely — `_send()` delegates to `subprocess.run()` and `_read()` reads files directly. No Netmiko session needed.

**2. Capability probe** — `_probe()` runs once per connection. It reads `/etc/os-release` for distro identity, then fires a single compound shell command with ~20 `command -v` and `test -f` checks:

```
command -v systemctl >/dev/null 2>&1 && echo CAP:has_systemd ;
command -v docker >/dev/null 2>&1 && echo CAP:has_docker ;
command -v nvidia-smi >/dev/null 2>&1 && echo CAP:has_nvidia ;
test -f /etc/pve/local/pve-ssl.pem && echo CAP:has_proxmox ;
...
```

One SSH round-trip. The output is parsed into a `caps` dict:

```python
self.caps = {
    # Identity
    "distro_id": "ubuntu",
    "distro_family": "debian",
    "distro_name": "Ubuntu 22.04.2 LTS",
    "distro_version": "22.04",
    # Init
    "has_systemd": True,
    "has_openrc": False,
    # Networking
    "has_lldpd": False,
    "has_frr": False,
    "has_bird": False,
    # Containers
    "has_docker": True,
    "has_podman": False,
    "has_proxmox": False,
    "has_libvirt": True,
    "is_container": False,
    # Hardware
    "has_thermal": True,
    "has_lm_sensors": True,
    "has_nvidia": True,
    "has_amdgpu": False,
    # Storage
    "has_zfs": False,
    "has_lvm": True,
    "has_smartctl": True,
}
```

The `distro_family` is derived from `ID` and `ID_LIKE` in os-release. Known families: `debian`, `rhel`, `alpine`, `arch`, `suse`, `cumulus`, `vyos`, `unknown`. Cumulus auto-sets `has_frr = True`.

After reconnect, `_probed` resets to `False` and the probe runs again on the next poll — the host's capabilities may have changed (package installed, service removed).

**3. Registry-driven collection** — `COLLECTOR_REGISTRY` is a list of `(data_key, method_name, gate)` tuples:

```python
COLLECTOR_REGISTRY = [
    # Always-on core
    ("system",       "_collect_system",       None),
    ("cpu",          "_collect_cpu",          None),
    ("memory",       "_collect_memory",       None),
    ("storage",      "_collect_storage",      None),
    ("interfaces",   "_collect_interfaces",   None),
    ("routes",       "_collect_routes",       None),
    ("connections",  "_collect_connections",   None),
    ("logging",      "_collect_journal",      None),
    # Capability-gated
    ("thermal",      "_collect_thermal",      "has_thermal"),
    ("lldp",         "_collect_lldp",         "has_lldpd"),
    ("services",     "_collect_services",     "has_systemd"),
    ("services_rc",  "_collect_services_rc",  "has_openrc"),
    ("docker",       "_collect_docker",       "has_docker"),
    ("podman",       "_collect_podman",       "has_podman"),
    ("gpu_nvidia",   "_collect_gpu_nvidia",   "has_nvidia"),
    ("gpu_amd",      "_collect_gpu_amd",      "has_amdgpu"),
    ("frr",          "_collect_frr",          "has_frr"),
    ("bird",         "_collect_bird",         "has_bird"),
    ("proxmox",      "_collect_proxmox",      "has_proxmox"),
    ("libvirt",      "_collect_libvirt",      "has_libvirt"),
    ("zfs",          "_collect_zfs",          "has_zfs"),
    ("lvm",          "_collect_lvm",          "has_lvm"),
    ("smart",        "_collect_smart",        "has_smartctl"),
]
```

Gate logic:
- `None` → always run
- `"cap_name"` → run if `self.caps[cap_name]` is truthy
- `"!cap_name"` → run if `self.caps[cap_name]` is falsy

`collect()` iterates the registry, skips gated-out collectors, times each one individually, and records timing in `meta.collector_timing`:

```json
{
  "meta": {
    "poll_count": 12,
    "poll_time": 3.41,
    "collectors_run": 14,
    "collectors_skipped": 9,
    "collector_timing": {
      "system": 0.082,
      "cpu": 0.241,
      "memory": 0.003,
      "docker": 0.873,
      "gpu_nvidia": 0.412,
      "logging": 0.198
    }
  },
  "caps": { ... }
}
```

**New collectors added in this phase:**

| Collector | Gate | Data Source | Notes |
|-----------|------|-----------|-------|
| `docker` | `has_docker` | `docker ps -a`, `docker stats --no-stream` | Container list + live CPU/mem/net per running container |
| `podman` | `has_podman` | `podman ps -a` | Same structure as Docker, no live stats yet |
| `gpu_nvidia` | `has_nvidia` | `nvidia-smi --query-gpu`, `--query-compute-apps` | Temp, util, VRAM, power, clocks, running processes |
| `gpu_amd` | `has_amdgpu` | `/sys/class/drm/card*/device/` | gpu_busy_percent, temp, VRAM from sysfs |
| `frr` | `has_frr` | `vtysh -c 'show bgp summary json'`, OSPF, route summary | JSON-first with text fallback. Cumulus boxes render like Arista |
| `bird` | `has_bird` | `birdc show protocols all`, `show route count` | Protocol summary and route count |
| `proxmox` | `has_proxmox` | `pvesh get /nodes/localhost/qemu\|lxc\|status` | QEMU VMs + LXC containers + node status, all JSON |
| `libvirt` | `has_libvirt` | `virsh list --all --title` | KVM domain list with state |
| `zfs` | `has_zfs` | `zpool list -Hp`, `zpool status -x` | Pool usage + health |
| `lvm` | `has_lvm` | `vgs`, `lvs` | Volume groups and logical volumes |
| `smart` | `has_smartctl` | `smartctl -H -A --json` | Per-disk health, temperature, power-on hours |
| `services_rc` | `has_openrc` | `rc-status --all` | OpenRC service list for Alpine/Gentoo |

---

### Phase 2 — Frontend Adaptation

**Status: Not started**

The frontend receives the `caps` dict in every WebSocket push. The `render()` function uses it to decide which panels to build. No capabilities, no panel — no more blank boxes.

**Panel visibility rules:**

```javascript
function render(data) {
  // Always render
  renderHeader(data);
  renderCompute(data);
  renderMemory(data);
  renderStorage(data);
  renderInterfaces(data);
  renderRoutes(data);
  renderConnections(data);
  renderEventLog(data);

  // Gated panels
  if (data.caps.has_thermal)   renderThermal(data);
  if (data.caps.has_lldpd)     renderLLDP(data);
  if (data.caps.has_systemd)   renderServices(data);
  if (data.caps.has_openrc)    renderServicesRC(data);
  if (data.caps.has_docker)    renderDocker(data);
  if (data.caps.has_podman)    renderPodman(data);
  if (data.caps.has_nvidia)    renderGPU(data);
  if (data.caps.has_amdgpu)    renderGPU_AMD(data);
  if (data.caps.has_frr)       renderFRR(data);
  if (data.caps.has_proxmox)   renderProxmox(data);
  if (data.caps.has_libvirt)   renderLibvirt(data);
  if (data.caps.has_zfs)       renderZFS(data);
  if (data.caps.has_lvm)       renderLVM(data);
  if (data.caps.has_smartctl)  renderSMART(data);
}
```

**Grid layout adaptation.** The current 3-column grid assumes a fixed panel set. With variable panels, the grid needs to reflow. Two approaches:

1. **Column assignment by category** — left column gets compute/hardware (CPU, memory, thermal, GPU, storage), center gets network (interfaces, LLDP, routes, FRR/BGP/OSPF), right gets operational (services, Docker/Proxmox, connections, event log). Empty columns collapse.

2. **CSS grid auto-placement** — let the browser pack panels into a 3-column grid with `grid-auto-flow: dense`. Simpler, but less predictable ordering.

Recommendation: option 1. Network engineers expect topology and routing on the same side of the screen. Predictable layout builds muscle memory.

**New panel designs needed:**

| Panel | Layout | Key Elements |
|-------|--------|-------------|
| Docker | Table with status dots | Container name, image, state, CPU%, mem usage, net I/O |
| GPU (NVIDIA) | Arc gauge + stats | Temperature gauge, utilization bar, VRAM bar, power draw, process list |
| FRR BGP | Table (mirrors Arista BGP panel) | Neighbor, ASN, state, prefixes received/sent, uptime |
| FRR OSPF | Table (mirrors Arista OSPF panel) | Neighbor ID, area, state, interface, dead time |
| Proxmox VMs | Table with status dots | VMID, name, status, CPUs, memory used/max, uptime |
| ZFS | Bar chart + health badge | Pool name, used/free bars, health status, frag% |

**Header adaptation.** The header currently shows hostname, distro, kernel, uptime. Add the distro family badge (derived from `caps.distro_family`) and a capability summary. Something like:

```
ThinkStation  Ubuntu 22.04.2 LTS  6.5.0-44-generic  x86_64
                                          UPTIME 16d 3h 8m  ● NOMINAL  ◆ AMBER
docker nvidia systemd lm-sensors lvm
```

The capability tags at the bottom of the header tell the operator at a glance what this host is running — useful when you're flipping between HUD tabs for different hosts.

**Footer adaptation.** Add collector timing to the footer status line:

```
POLL:14 | 3.41s | CPU:1%/0% | FAN:--- | docker:0.87s nvidia:0.41s
```

---

### Phase 3 — Distro Testing Matrix

**Status: Not started**

The probe and gated collectors need validation across distro families. Each row in this matrix represents a test target — either a real host, a VM in EVE-NG, or a Docker container.

| Distro | Family | Init | Test Target | Expected Caps |
|--------|--------|------|-------------|---------------|
| Ubuntu 22.04 | debian | systemd | ThinkStation (local) | thermal, lm-sensors, nvidia, docker, systemd, lvm |
| Ubuntu 24.04 | debian | systemd | VM or container | thermal, systemd |
| Debian 12 | debian | systemd | VM | thermal, systemd |
| Rocky 9 | rhel | systemd | VM | thermal, systemd |
| Alpine 3.19 | alpine | openrc | Docker container | openrc (no systemd) |
| Cumulus Linux | cumulus | systemd | EVE-NG image | frr, lldpd, systemd |
| VyOS | vyos | systemd | EVE-NG image | frr or bird, systemd |
| Proxmox VE 8 | debian | systemd | If available | proxmox, systemd, zfs (often), lvm |

**Test procedure per target:**

1. Run `_probe()` standalone, verify `caps` dict matches expected
2. Run full `collect()`, verify no errors in `meta`, verify gated collectors skipped correctly
3. Confirm `collector_timing` is populated for all collectors that ran
4. Verify frontend renders only the panels supported by that host (Phase 2)

**Known edge cases to validate:**

- Alpine: no `systemctl`, no `journalctl` — should fall back to syslog/messages in `_collect_journal()`, should run `_collect_services_rc()` instead of `_collect_services()`
- Cumulus: `vtysh` may require `sudo` or `netd` group membership — collector should handle permission denied gracefully
- Docker inside Docker: `is_container` detection should not prevent Docker collector from running (the host Docker socket might be bind-mounted)
- WSL: `is_wsl` detected but most collectors still work — may want to suppress thermal/fan panels
- Minimal containers: many tools missing (`ps`, `ss`, `ip`) — core collectors need to handle empty output gracefully (they already do, but validate)

---

### Phase 4 — Operational Polish

**Status: Not started**

Refinements after the core pipeline is validated:

**Progress overlay.** The existing overlay shows command names during collection. Update it to show collector names from the registry: `"COLLECTING DOCKER..."`, `"DOCKER ✓"`. Skip gated-out collectors in the progress display — don't show `"SKIPPING LLDP"`, just omit it.

**Stale data handling.** The `_stale_or_error()` pattern from the Arista collector is implemented. Frontend needs to render the stale badge (amber border on header, `STALE` badge next to uptime) when `meta.stale === true`.

**Delta counters.** Interface TX/RX bytes and Docker net I/O are cumulative counters. The frontend should compute and display per-poll deltas (bytes/sec) rather than raw totals. Store the previous payload and diff on each render.

**GPU process cross-reference.** The NVIDIA collector returns running compute processes with PID and VRAM. Cross-reference with the CPU top-process list to show which processes are using both CPU and GPU — useful for spotting Ollama, training jobs, etc.

**Journal severity filtering.** The event log panel currently shows ALL entries. Add severity tabs mirroring the Arista pattern: ALL | WARN+ | KERNEL. For systemd hosts, WARN+ maps to `priority <= 4` (warning and above). KERNEL maps to `_TRANSPORT == "kernel"` or `SYSLOG_IDENTIFIER == "kernel"`.

**Probe caching across reconnects.** Currently the probe re-runs on every reconnect. For hosts where capabilities don't change (the ThinkStation isn't going to lose Docker between reconnects), consider caching the last probe result and only re-probing if the distro/kernel changed. Low priority — the probe is one SSH round-trip.

---

### Phase 5 — Future: Fleet Awareness

**Status: Conceptual**

Not in scope for this rewrite, but the architecture enables it. The `caps` dict is a structured inventory of every host the HUD has connected to. A future multi-target mode could:

- Cycle through a list of hosts, probing and collecting from each
- Build a fleet summary view: "14 hosts, 8 have Docker, 3 have NVIDIA GPUs, 2 run FRR"
- Render a grid of mini-HUDs, one per host, each showing only their relevant panels
- Serve as a lightweight CMDB replacement for capability discovery — no agents, no registration, just SSH and `/proc`

This is a different tool, not a modification of the single-device HUD. But the collector and probe infrastructure built in Phase 1 is the foundation it would run on.

---

## File Changes

| File | Status | Notes |
|------|--------|-------|
| `collector.py` | **Rewritten** | Persistent session, probe, registry, 23 collectors |
| `server.py` | **No changes needed** | Already calls `collector.collect()` and pushes the dict. The `caps` key flows through transparently. Remove the `finally: disconnect()` in the old poll loop if still present. |
| `config.yaml` | **No changes needed** | Same device config structure |
| `static/index.html` | **Phase 2** | Caps-driven panel rendering, new panel designs |

## Server Compatibility Note

The server's `/api/connect` hot-swap path creates a new `LinuxCollector` instance. The new collector will probe on first `collect()` call — no server changes needed. The `/api/defaults` and `/api/status` endpoints work as-is. The terminal proxy (`/ws/terminal`) is independent of the collector and unchanged.

The only server-side consideration: the old `poll_loop()` may still have a `finally` block that disconnects the collector after each poll. If present, remove it — the persistent session model requires the connection to stay open across cycles.

---

## Dependencies

No new dependencies. The collector uses only:

- `netmiko` — SSH session management (existing)
- `paramiko` — terminal proxy (existing, via server.py)
- Standard library: `json`, `re`, `subprocess`, `time`, `pathlib`, `logging`

All new collectors use commands available in base installs (`docker`, `nvidia-smi`, `vtysh`, `zpool`, `virsh`, `smartctl`). The probe detects their presence before attempting to use them — no ImportError, no crash, no empty panels.