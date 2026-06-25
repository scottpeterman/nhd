"""
Persistence + CRUD for the session tree.

The POC tree was read-only: a file went in via load_termtels()/load_nethuds_
devices() and never came back out. SessionStore makes it editable and durable.
It owns the authoritative list of DeviceSession objects (the same objects the
tree items reference), mutates them in place, and writes them back to disk in
the termtels format the loaders already read -- so a saved file reloads
identically.

Secrets never round-trip: save() writes a credential *name* and never a
password. device_type is written in its canonical netmiko form so it reloads
without depending on hint inference.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .sessions import DeviceSession, load_termtels, load_termtels_groups

_UNGROUPED = "Ungrouped"


class SessionStore:
    """In-memory session list with file-backed load/save and CRUD.

    The store edits DeviceSession objects by identity (the same instances held
    in tree items), so callers can hold a reference, edit it, and ask the store
    to persist. `dirty` tracks unsaved changes; `path` is the file edits are
    written back to (None until a file is loaded or a save location is chosen).
    """

    def __init__(self):
        self.sessions: list[DeviceSession] = []
        self.path: Path | None = None
        self.dirty = False
        # Folders the user created that hold no session yet. Groups are otherwise
        # derived from the sessions in them, so without this an empty folder
        # could neither exist nor round-trip. A name leaves this list the moment
        # a session joins it (it becomes a normal derived group) and is written
        # back as `{folder_name: X, sessions: []}` so it survives save/reload.
        self._empty_groups: list[str] = []

    # ---- load / save --------------------------------------------------------

    def load(self, path: str | Path) -> None:
        """Replace the session list from a termtels file and adopt it as the
        save target."""
        self.sessions = load_termtels(path)
        self.path = Path(path)
        self.dirty = False
        # Pick up folders declared in the file that hold no session, so an empty
        # folder the user saved comes back as an empty folder.
        used = {s.group or _UNGROUPED for s in self.sessions}
        self._empty_groups = [g for g in dict.fromkeys(load_termtels_groups(path))
                              if g not in used]

    def adopt(self, sessions: list[DeviceSession], path: str | Path | None = None) -> None:
        """Take an externally-loaded session list (e.g. a devices.yaml import).
        A devices.yaml is not the native save format, so path stays None until
        the caller chooses a save location, which avoids silently rewriting an
        import in a different shape."""
        self.sessions = list(sessions)
        self.path = Path(path) if path else None
        self.dirty = False
        self._empty_groups = []

    def new_file(self) -> None:
        """Reset to an empty, unsaved session set (File → New session file).
        Clears the save target so the first save prompts for a location."""
        self.sessions = []
        self._empty_groups = []
        self.path = None
        self.dirty = False

    def to_yaml(self) -> str:
        """Serialize to the grouped termtels structure the loaders read back."""
        groups: dict[str, list[dict]] = {}
        for s in self.sessions:
            groups.setdefault(s.group or _UNGROUPED, []).append(self._session_dict(s))
        # Carry empty folders through as `{folder_name, sessions: []}` so a
        # folder created in the UI survives a save/reload with no session in it.
        for g in self._empty_groups:
            groups.setdefault(g, [])
        doc = {"sessions": [
            {"folder_name": group, "sessions": items}
            for group, items in groups.items()
        ]}
        return yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)

    def save(self, path: str | Path | None = None) -> Path:
        """Write to `path` (or the adopted path). Returns the path written.
        Raises ValueError if no path is known."""
        target = Path(path) if path else self.path
        if target is None:
            raise ValueError("No save path set for sessions")
        target.write_text(self.to_yaml())
        self.path = target
        self.dirty = False
        return target

    @staticmethod
    def _session_dict(s: DeviceSession) -> dict:
        """One session as a YAML node. Omits empties and NEVER writes a
        password -- authentication is a vault credential reference."""
        d: dict = {"display_name": s.name, "host": s.host}
        if s.device_type:
            d["device_type"] = s.device_type          # canonical -> exact reload
        if s.credential:
            d["credential"] = s.credential
        if s.tags:
            d["tags"] = list(s.tags)
        if s.username and not s.credential:
            d["username"] = s.username
        if s.port and s.port != 22:
            d["port"] = s.port
        if s.legacy_ssh:
            d["legacy_ssh"] = True
        if s.key_file:
            d["key_file"] = s.key_file                # a path, not a secret
        return d

    # ---- CRUD ---------------------------------------------------------------

    def add(self, session: DeviceSession) -> DeviceSession:
        self.sessions.append(session)
        # A folder gains its first session: it's now a normal derived group.
        self._discard_empty(session.group or _UNGROUPED)
        self.dirty = True
        return session

    def add_group(self, name: str) -> bool:
        """Create an empty folder. Returns False if the name is blank or a
        folder/group by that name already exists (so the caller can warn)."""
        name = (name or "").strip()
        if not name:
            return False
        if name in self.groups():
            return False
        self._empty_groups.append(name)
        self.dirty = True
        return True

    def _discard_empty(self, group: str) -> None:
        if group in self._empty_groups:
            self._empty_groups.remove(group)

    def remove(self, session: DeviceSession) -> bool:
        for i, s in enumerate(self.sessions):
            if s is session:
                del self.sessions[i]
                self.dirty = True
                return True
        return False

    def mark_dirty(self) -> None:
        """Call after editing a DeviceSession in place so the change persists."""
        self.dirty = True

    def duplicate(self, session: DeviceSession) -> DeviceSession:
        """Copy a session under a '(copy)' name, inserted right after it."""
        from dataclasses import replace
        copy = replace(session, name=self._unique_name(f"{session.name} (copy)"),
                       tags=list(session.tags))
        idx = next((i for i, s in enumerate(self.sessions) if s is session),
                   len(self.sessions) - 1)
        self.sessions.insert(idx + 1, copy)
        self.dirty = True
        return copy

    def rename_group(self, old: str, new: str) -> int:
        """Move every session in group `old` to `new`. Returns count moved
        (counting an empty-folder rename as a change so it persists)."""
        new = new.strip()
        n = 0
        for s in self.sessions:
            if (s.group or _UNGROUPED) == old:
                s.group = new
                n += 1
        if old in self._empty_groups:
            self._empty_groups.remove(old)
            if new not in self.groups():
                self._empty_groups.append(new)
            n = max(n, 1)
        if n:
            self.dirty = True
        return n

    def remove_group(self, group: str) -> int:
        """Delete a folder and every session in it. Returns count removed."""
        before = len(self.sessions)
        self.sessions = [s for s in self.sessions
                         if (s.group or _UNGROUPED) != group]
        removed = before - len(self.sessions)
        if group in self._empty_groups:
            self._empty_groups.remove(group)
            removed = max(removed, 1)
        if removed:
            self.dirty = True
        return removed

    # ---- helpers ------------------------------------------------------------

    def groups(self) -> list[str]:
        """Distinct folder names in first-seen order, including empty folders."""
        seen: dict[str, None] = {}
        for s in self.sessions:
            seen.setdefault(s.group or _UNGROUPED, None)
        for g in self._empty_groups:
            seen.setdefault(g, None)
        return list(seen)

    def _unique_name(self, base: str) -> str:
        existing = {s.name for s in self.sessions}
        if base not in existing:
            return base
        i = 2
        while f"{base} {i}" in existing:
            i += 1
        return f"{base} {i}"