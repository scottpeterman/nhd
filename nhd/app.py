"""
nethuds-desktop: a multi-tab PyQt6 wrapper around the vendor HUD servers.

Architecture (the "easy path"):
  * ServerManager runs each vendor's FastAPI app in-process on 127.0.0.1.
  * Each tab is a QWebEngineView pointed at that vendor server's root URL.
  * Credentials are injected into the existing login modal on load and the
    page's own connect() is invoked -- so the HUD pages are used verbatim,
    no QWebChannel bridge, no JS edits. The page's `location.host`-relative
    WebSocket means it reconnects to whatever port we bound.

Run:  nethuds-desktop  [--session-file path]  [--devices path]
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

from PyQt6.QtCore import Qt, QUrl, QSettings
from PyQt6.QtGui import (
    QAction, QActionGroup, QKeySequence, QPalette, QColor, QShortcut)
from PyQt6.QtWidgets import (
    QApplication, QDialog, QFileDialog, QInputDialog, QLineEdit, QMainWindow,
    QMenu, QMessageBox, QSplitter, QTabWidget, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)
from PyQt6.QtWebEngineWidgets import QWebEngineView

from .server_manager import ServerManager, VENDOR_MODULES
from .sessions import DeviceSession, load_nethuds_devices, load_termtels
from .session_store import SessionStore
from .vault import CredentialStore, CredentialResolver, ResolvedIdentity
from .connect import ConnectWorker
from .dialogs import (
    ensure_unlocked, SessionEditDialog, ConnectAuthDialog,
    CredentialManagerDialog, AboutDialog,
)


class IdentityError(Exception):
    """Resolving a session's connect identity failed in a way worth showing the
    user (locked vault, missing credential, unreadable key file)."""


class ConnectCancelled(Exception):
    """The user dismissed the connect-time auth prompt; abort silently with no
    error splash and no tab."""

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
                    datefmt="%H:%M:%S")
logger = logging.getLogger("nethuds.desktop")

# Chrome-style zoom stops the View → Zoom menu steps through. Bounds stay inside
# QtWebEngine's supported 0.25–5.0 range.
ZOOM_LEVELS = [0.5, 0.67, 0.75, 0.8, 0.9, 1.0, 1.1, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0]

# Discrete UI scale factors offered in View → Scale Factor. Unlike Zoom (which
# is the HUD page's own zoom and applies live), this is the Qt application scale
# (QT_SCALE_FACTOR), read in main() before QApplication is built — so a change
# is persisted to QSettings and takes effect on the next launch, not live.
SCALE_FACTORS = [1.0, 1.25, 1.5, 1.75, 2.0, 2.5]

# QSettings scope. Native backend per platform (registry / plist / .conf);
# nothing here is a secret — geometry, zoom, and the last session-file path
# (a path, never a credential). The vault remains the only store of secrets.
SETTINGS_ORG = "nethuds"
SETTINGS_APP = "nhd"


class HudTab(QWidget):
    """One device, rendered by its vendor HUD server inside a web view.

    Two connect paths share this tab:

      * Identity path (vault credential or an inline secret): the wrapper POSTs
        /api/connect itself via a ConnectWorker, off the UI thread, then loads
        the page pointed at the established session so it *attaches*. This is
        the only path that can carry a private key (key_text never rides a URL).
      * Legacy path (session has no secret of its own): the page autoconnects
        against the vendor yaml defaults, exactly as the original POC did.

    `identity_provider(session)` is resolved on the UI thread (the vault unlock
    prompt is modal) and returns a ResolvedIdentity, or None to take the legacy
    path. It may raise IdentityError to abort with a message.
    """

    def __init__(self, session: DeviceSession, servers: ServerManager,
                 identity_provider):
        super().__init__()
        self.session = session
        self.servers = servers
        self._server = None      # RunningServer this tab is bound to
        self._worker = None      # ConnectWorker while a connect is in flight
        self.cancelled = False   # user dismissed the connect-time auth prompt

        self.view = QWebEngineView(self)
        # Zoom is re-applied after every navigation: QtWebEngine resets the
        # factor on a fresh page load, and this tab navigates at least once
        # (splash -> attached HUD), so without this the zoom would snap back.
        self._zoom = 1.0
        self.view.loadFinished.connect(
            lambda _ok: self.view.setZoomFactor(self._zoom))
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.view)

        if session.vendor not in VENDOR_MODULES:
            self._fail(f"No HUD server for vendor '{session.vendor}'")
            return

        # Resolve identity first -- it may pop a modal prompt or be cancelled,
        # and it needs no server, so doing it before acquire() means a cancelled
        # connect leaves nothing to tear down.
        try:
            identity = identity_provider(session)
        except ConnectCancelled:
            self.cancelled = True
            return
        except IdentityError as e:
            self._fail(str(e))
            return

        try:
            self._server = servers.acquire(session.vendor)
        except Exception as e:  # pragma: no cover - defensive
            self._fail(f"Failed to start {session.vendor} HUD: {e}")
            return

        if identity is None:
            self._load_legacy_autoconnect()
        else:
            self._establish_and_attach(identity)

    # ---- identity path: wrapper establishes, page attaches ----
    def _establish_and_attach(self, identity: ResolvedIdentity):
        self._splash(f"Connecting to {self.session.host} as {identity.username}…",
                     f"({identity.source or 'inline'})")
        self._worker = ConnectWorker(
            self._server.base_url, identity, self.session.host,
            port=self.session.port, parent=self,
        )
        self._worker.connected.connect(self._on_connected)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _on_connected(self, result):
        # Session vendors hand back an id to attach to; single-target Linux
        # establishes its one device and needs no id (the page's no-params
        # branch attaches telemetry to the live collector).
        params = {"name": self.session.name}
        if result.session_id:
            params["session"] = result.session_id
        logger.info("Attaching %s HUD for %r (session=%s)",
                    self.session.vendor, self.session.name,
                    result.session_id or "<linux/none>")
        self.view.load(QUrl(f"{self._server.base_url}/?{urlencode(params)}"))
        self._worker = None

    def _on_failed(self, msg: str):
        self._fail(f"Connection to {self.session.host} failed:\n\n{msg}")
        self._worker = None

    # ---- legacy path: page autoconnects against vendor yaml defaults ----
    def _load_legacy_autoconnect(self):
        s = self.session
        params = {
            "host": s.host,
            "username": s.username,
            "device_type": s.device_type,
            "name": s.name,
            "autoconnect": "true",
        }
        if s.legacy_ssh:
            params["legacy_ssh"] = "true"
        logger.info("Loading %s HUD for %r via vendor-default autoconnect",
                    s.vendor, s.name)
        if not s.username:
            logger.warning("Session %r has no username and no credential; the "
                           "HUD server will use its vendor yaml identity", s.name)
        self.view.load(QUrl(f"{self._server.base_url}/?{urlencode(params)}"))

    def _splash(self, line1: str, line2: str = ""):
        self.view.setHtml(
            "<body style='background:#0a0a0a;color:#0c8;font-family:monospace;"
            "padding:24px'>"
            f"<div style='font-size:15px'>{line1}</div>"
            f"<div style='color:#888;margin-top:6px'>{line2}</div>"
            "</body>"
        )

    def _fail(self, msg: str):
        safe = msg.replace("<", "&lt;").replace("\n", "<br>")
        self.view.setHtml(
            f"<body style='background:#0a0a0a;color:#e33;font-family:monospace;"
            f"padding:24px;white-space:pre-wrap'>{safe}</body>"
        )

    def apply_zoom(self, factor: float):
        """Set this tab's web-view zoom and remember it so it survives the
        next navigation (see the loadFinished hook in __init__)."""
        self._zoom = factor
        self.view.setZoomFactor(factor)

    def shutdown(self):
        """Stop any in-flight connect and release the backing server (stops it
        only if dedicated)."""
        if self._worker is not None and self._worker.isRunning():
            self._worker.wait(2000)
        self._worker = None
        self.servers.release(self._server)
        self._server = None


class MainWindow(QMainWindow):
    def __init__(self, session_store: SessionStore, initial_file=(None, None)):
        super().__init__()
        self.setWindowTitle("nethuds desktop")
        self.resize(1500, 900)
        self.settings = QSettings(SETTINGS_ORG, SETTINGS_APP)
        self.servers = ServerManager(host="127.0.0.1")
        self.store = CredentialStore()
        self.resolver = CredentialResolver(self.store)
        self.sessions = session_store
        # (path, kind) of the file to reopen next launch; kind is "termtels"
        # (native save target) or "devices" (re-imported, never rewritten).
        # Seeded from whatever main() loaded (CLI arg or the restored last file).
        self._last_file = initial_file
        self._last_open = (None, 0.0)  # (item, monotonic) for debounce
        self._zoom = 1.0               # global HUD zoom, applied to every tab

        # --- session tree (left), with a live filter box on top ---
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Sessions"])
        # itemActivated covers double-click and Enter. On macOS the tree
        # activates on single click, so a double-click fires this twice -- the
        # _open_from_item debounce collapses that into one open.
        self.tree.itemActivated.connect(self._open_from_item)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._tree_menu)

        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter — name, host, tag, vendor, group…")
        self.filter.setClearButtonEnabled(True)
        self.filter.textChanged.connect(self._apply_filter)
        # Ctrl+F focuses the filter; Esc clears it while it has focus.
        QShortcut(QKeySequence("Ctrl+F"), self, activated=self._focus_filter)
        esc = QShortcut(QKeySequence("Escape"), self.filter)
        esc.setContext(Qt.ShortcutContext.WidgetShortcut)
        esc.activated.connect(self.filter.clear)

        left = QWidget()
        left.setMaximumWidth(320)
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.setSpacing(4)
        lv.addWidget(self.filter)
        lv.addWidget(self.tree)

        # --- tabs (right) ---
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.tabCloseRequested.connect(self._close_tab)
        # Right-click the tab bar for close current / others / right / all.
        bar = self.tabs.tabBar()
        bar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        bar.customContextMenuRequested.connect(self._tab_menu)

        self.split = QSplitter(Qt.Orientation.Horizontal)
        self.split.addWidget(left)
        self.split.addWidget(self.tabs)
        self.split.setStretchFactor(1, 1)
        self.setCentralWidget(self.split)

        self._build_menu()
        self._refresh_tree()
        self._restore_ui_state()

    # ---- menu ----
    def _build_menu(self):
        m = self.menuBar().addMenu("&File")
        a_newfile = QAction("New session file", self)
        a_newfile.setShortcut(QKeySequence.StandardKey.New)  # Ctrl/Cmd+N
        a_newfile.triggered.connect(self._new_file)
        m.addAction(a_newfile)
        m.addSeparator()
        a_term = QAction("Open termtels session file…", self)
        a_term.triggered.connect(lambda: self._load_file(load_termtels, "termtels", native=True))
        a_dev = QAction("Open nethuds devices.yaml…", self)
        a_dev.triggered.connect(lambda: self._load_file(load_nethuds_devices, "devices", native=False))
        m.addAction(a_term)
        m.addAction(a_dev)
        m.addSeparator()
        a_new = QAction("New session…", self)
        a_new.triggered.connect(lambda: self._new_session())
        m.addAction(a_new)
        a_save = QAction("Save sessions", self)
        a_save.setShortcut("Ctrl+S")
        a_save.triggered.connect(self._save_sessions)
        a_save_as = QAction("Save sessions as…", self)
        a_save_as.triggered.connect(self._save_sessions_as)
        m.addAction(a_save)
        m.addAction(a_save_as)
        m.addSeparator()
        a_quit = QAction("Quit", self)
        a_quit.triggered.connect(self.close)
        m.addAction(a_quit)

        v = self.menuBar().addMenu("&Vault")
        a_unlock = QAction("Unlock / create vault…", self)
        a_unlock.triggered.connect(self._unlock_vault)
        a_manage = QAction("Manage credentials…", self)
        a_manage.triggered.connect(self._manage_credentials)
        a_lock = QAction("Lock vault", self)
        a_lock.triggered.connect(self._lock_vault)
        v.addAction(a_unlock)
        v.addAction(a_manage)
        v.addSeparator()
        v.addAction(a_lock)

        view = self.menuBar().addMenu("&View")
        zoom = view.addMenu("Zoom")
        a_zin = QAction("Zoom In", self)
        # Qt maps Ctrl -> Cmd on macOS, so these are Cmd +/-/0 there. Two
        # bindings for zoom-in cover both the '+' and the unshifted '=' key.
        a_zin.setShortcuts([QKeySequence("Ctrl++"), QKeySequence("Ctrl+=")])
        a_zin.triggered.connect(self._zoom_in)
        a_zout = QAction("Zoom Out", self)
        a_zout.setShortcut(QKeySequence("Ctrl+-"))
        a_zout.triggered.connect(self._zoom_out)
        a_zreset = QAction("Actual Size (100%)", self)
        a_zreset.setShortcut(QKeySequence("Ctrl+0"))
        a_zreset.triggered.connect(self._zoom_reset)
        zoom.addAction(a_zin)
        zoom.addAction(a_zout)
        zoom.addSeparator()
        zoom.addAction(a_zreset)
        zoom.addSeparator()
        self._zoom_readout = QAction("Current zoom: 100%", self)
        self._zoom_readout.setEnabled(False)
        zoom.addAction(self._zoom_readout)

        # Application scale factor (distinct from HUD zoom above). Exclusive,
        # radio-style: Auto detects from the display; a preset forces it. The
        # choice persists to QSettings (ui/scale) and applies on next launch.
        scale_menu = view.addMenu("Scale Factor")
        self._scale_group = QActionGroup(self)
        self._scale_group.setExclusive(True)
        current = self.settings.value("ui/scale", 0.0, type=float)

        def _add_scale(label: str, value: float) -> QAction:
            a = QAction(label, self)
            a.setCheckable(True)
            a.setData(value)
            a.triggered.connect(lambda _checked=False, v=value: self._set_scale_factor(v))
            self._scale_group.addAction(a)
            scale_menu.addAction(a)
            return a

        auto_action = _add_scale("Auto (detect from display)", 0.0)
        scale_menu.addSeparator()
        matched = False
        for f in SCALE_FACTORS:
            a = _add_scale(f"{int(round(f * 100))}%", f)
            if current > 0 and abs(current - f) < 1e-6:
                a.setChecked(True)
                matched = True
        # A --scale value that isn't a preset still shows, checked, so the menu
        # always reflects the effective scale.
        if current > 0 and not matched:
            _add_scale(f"{current:g}× (current)", current).setChecked(True)
        if current <= 0:
            auto_action.setChecked(True)

        helpm = self.menuBar().addMenu("&Help")
        a_about = QAction("About nethuds desktop", self)
        # AboutRole = native placement: macOS moves this to the application menu
        # (the "nethuds desktop ▸ About" spot a Mac user expects); on Windows and
        # Linux it stays under Help. Use QAction.MenuRole.NoRole instead to force
        # it under Help on macOS too.
        a_about.setMenuRole(QAction.MenuRole.AboutRole)
        a_about.triggered.connect(self._about)
        helpm.addAction(a_about)

    def _about(self):
        AboutDialog(self).exec()

    def _unlock_vault(self):
        if ensure_unlocked(self.store, self):
            n = len(self.store.list_credentials())
            self.statusBar().showMessage(
                f"Vault unlocked — {n} credential(s) available")

    def _lock_vault(self):
        self.store.lock()
        self.statusBar().showMessage("Vault locked")

    def _manage_credentials(self):
        # The manager opens against any lock state: the metadata list works
        # locked, and it offers its own inline unlock for the secret-touching
        # actions. No need to force an unlock here.
        CredentialManagerDialog(self.store, self).exec()
        if self.store.is_initialized() and self.store.is_unlocked:
            n = len(self.store.list_credentials())
            self.statusBar().showMessage(f"Vault unlocked — {n} credential(s)")

    # ---- view / zoom ----
    @staticmethod
    def _step_zoom(current: float, direction: int) -> float:
        """Next stop above (direction>0) or below the current factor, snapping
        from any in-between value (e.g. one set by Ctrl+scroll on Linux)."""
        if direction > 0:
            return next((z for z in ZOOM_LEVELS if z > current + 1e-6),
                        ZOOM_LEVELS[-1])
        return next((z for z in reversed(ZOOM_LEVELS) if z < current - 1e-6),
                    ZOOM_LEVELS[0])

    def _set_zoom(self, factor: float):
        """Clamp, store as the global preference, and apply to every open tab."""
        factor = max(ZOOM_LEVELS[0], min(ZOOM_LEVELS[-1], factor))
        self._zoom = factor
        for i in range(self.tabs.count()):
            w = self.tabs.widget(i)
            if isinstance(w, HudTab):
                w.apply_zoom(factor)
        pct = round(factor * 100)
        self._zoom_readout.setText(f"Current zoom: {pct}%")
        self.statusBar().showMessage(f"Zoom {pct}%", 1500)

    def _zoom_in(self):
        self._set_zoom(self._step_zoom(self._zoom, +1))

    def _zoom_out(self):
        self._set_zoom(self._step_zoom(self._zoom, -1))

    def _zoom_reset(self):
        self._set_zoom(1.0)

    def _set_scale_factor(self, value: float):
        """Persist the chosen application scale to QSettings (ui/scale) — read
        in main() before QApplication is built. Qt fixes the scale at launch, so
        this can't apply live; we save it and tell the user a restart applies it.
        value <= 0 means Auto (clear the override, detect from the display).
        """
        if value and value > 0:
            self.settings.setValue("ui/scale", float(value))
            pretty = (f"{int(round(value * 100))}%"
                      if abs(value * 100 - round(value * 100)) < 1e-6
                      else f"{value:g}×")
            msg = f"Scale factor set to {pretty}."
        else:
            self.settings.remove("ui/scale")
            msg = "Scale factor set to automatic (detect from display)."
        self.settings.sync()   # flush now so the next launch reads it
        self.statusBar().showMessage(f"{msg} Restart to apply.", 6000)
        QMessageBox.information(
            self, "Scale factor",
            f"{msg}\n\nThe application scale is fixed when nethuds desktop "
            f"starts, so this takes effect the next time you launch it.\n\n"
            f"(View → Zoom changes the HUD page size live in the meantime.)")

    def _maybe_save_changes(self) -> bool:
        """Offer to save pending session edits before an action that would
        discard them (New file, opening another file, quitting). Returns True
        to proceed, False if the user cancelled (caller should abort)."""
        if not self.sessions.dirty:
            return True
        name = self.sessions.path.name if self.sessions.path else "this session set"
        btn = QMessageBox.question(
            self, "Unsaved changes",
            f"Save changes to {name} before continuing?",
            QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard
            | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Save)
        if btn == QMessageBox.StandardButton.Cancel:
            return False
        if btn == QMessageBox.StandardButton.Save:
            if self.sessions.path is None:
                self._save_sessions_as()
                return not self.sessions.dirty   # Save As cancelled -> still dirty
            self._save_sessions()
        return True

    def _new_file(self):
        """Start an empty, unsaved session set. The first save (Ctrl+S) picks a
        location, after which edits auto-persist like any loaded file."""
        if not self._maybe_save_changes():
            return
        self.sessions.new_file()
        self._last_file = (None, None)
        self.settings.remove("session/last_path")
        self.settings.remove("session/last_kind")
        self._refresh_tree()
        self.statusBar().showMessage(
            "New session file — add folders and sessions, then Save (Ctrl+S)")

    def _load_file(self, loader, label: str, native: bool):
        if not self._maybe_save_changes():
            return
        path, _ = QFileDialog.getOpenFileName(
            self, f"Open {label} file", "", "YAML (*.yaml *.yml);;All files (*)")
        if not path:
            return
        try:
            sessions = loader(path)
        except Exception as e:
            QMessageBox.critical(self, "Load failed", f"{path}\n\n{e}")
            return
        if not sessions:
            QMessageBox.information(self, "No devices", f"No sessions found in {path}")
            return
        # A termtels file is the native save format and becomes the save target;
        # a devices.yaml is an import, so we don't silently rewrite it in a
        # different shape -- the user picks a save location on first save.
        if native:
            self.sessions.load(path)
        else:
            self.sessions.adopt(sessions)
        self._remember_file(path, "termtels" if native else "devices")
        self._refresh_tree()
        self.statusBar().showMessage(
            f"Loaded {len(sessions)} session(s) from {Path(path).name}")

    # ---- persistence ----
    def _save_sessions(self):
        if self.sessions.path is None:
            return self._save_sessions_as()
        try:
            target = self.sessions.save()
        except Exception as e:
            QMessageBox.critical(self, "Save failed", str(e))
            return
        self._update_title()
        self.statusBar().showMessage(f"Saved {len(self.sessions.sessions)} session(s) to {target.name}")

    def _save_sessions_as(self):
        start = str(self.sessions.path) if self.sessions.path else "sessions.yaml"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save sessions as", start, "YAML (*.yaml *.yml);;All files (*)")
        if not path:
            return
        try:
            target = self.sessions.save(path)
        except Exception as e:
            QMessageBox.critical(self, "Save failed", str(e))
            return
        self._remember_file(str(target), "termtels")
        self._update_title()
        self.statusBar().showMessage(f"Saved {len(self.sessions.sessions)} session(s) to {target.name}")

    def _persist(self):
        """Auto-save after an edit when a file is known; otherwise leave the
        change in memory (the title shows the unsaved marker)."""
        if self.sessions.path is not None:
            try:
                self.sessions.save()
            except Exception as e:
                QMessageBox.critical(self, "Save failed", str(e))
        self._update_title()

    def _update_title(self):
        name = self.sessions.path.name if self.sessions.path else "(unsaved)"
        mark = " •" if self.sessions.dirty else ""
        self.setWindowTitle(f"nethuds desktop — {name}{mark}")

    # ---- session tree ----
    def _refresh_tree(self):
        """Rebuild the tree from the store. Leaf items hold the actual
        DeviceSession object (by reference), so edits mutate what's displayed."""
        expanded = self._expanded_groups()
        self.tree.clear()
        # Seed every known folder first — including empty ones the store tracks —
        # then file sessions into them, so a folder with no session still shows.
        groups: dict[str, list[DeviceSession]] = {
            g: [] for g in self.sessions.groups()}
        for s in self.sessions.sessions:
            groups.setdefault(s.group or "Ungrouped", []).append(s)
        for group, items in sorted(groups.items()):
            parent = QTreeWidgetItem([group])
            parent.setFlags(parent.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            parent.setData(0, Qt.ItemDataRole.UserRole, ("group", group))
            self.tree.addTopLevelItem(parent)
            for s in sorted(items, key=lambda x: x.name):
                leaf = QTreeWidgetItem([f"{s.name}  ({s.vendor})"])
                leaf.setData(0, Qt.ItemDataRole.UserRole, s)
                cred = f"cred:{s.credential}" if s.credential else (s.username or "vendor-default")
                leaf.setToolTip(0, f"{cred}@{s.host}:{s.port}  [{s.device_type}]"
                                   f"{'  legacy-ssh' if s.legacy_ssh else ''}")
                parent.addChild(leaf)
            if not items:
                # An empty folder reads as a folder, not a dead end.
                parent.setToolTip(0, "Empty folder — right-click to add a session")
            parent.setExpanded(group in expanded if expanded else True)
        self._update_title()
        # An edit rebuilds the tree; keep any active filter applied.
        if getattr(self, "filter", None) is not None and self.filter.text().strip():
            self._apply_filter(self.filter.text())

    def _expanded_groups(self) -> set[str]:
        out: set[str] = set()
        for i in range(self.tree.topLevelItemCount()):
            it = self.tree.topLevelItem(i)
            if it.isExpanded():
                out.add(it.text(0))
        return out

    # ---- filter ----
    def _focus_filter(self):
        self.filter.setFocus()
        self.filter.selectAll()

    @staticmethod
    def _haystack(s: DeviceSession, group_label: str) -> str:
        """All the text a session can be matched against, lower-cased."""
        return " ".join((
            s.name, s.host, s.vendor, s.device_type, s.group or "", group_label,
            s.username or "", s.credential or "", " ".join(s.tags or []),
        )).lower()

    def _apply_filter(self, text: str):
        """Show only sessions matching every whitespace-separated term (AND).
        Groups with no surviving child are hidden; groups with matches are
        expanded so hits are visible. An empty filter restores everything.

        Matching spans the whole session, not just the visible label — so
        'iad spine', 'arista', '@prompt', a tag, or a credential name all work.
        """
        terms = text.lower().split()
        any_match = False
        for i in range(self.tree.topLevelItemCount()):
            group_item = self.tree.topLevelItem(i)
            group_label = group_item.text(0).lower()
            visible = 0
            for j in range(group_item.childCount()):
                leaf = group_item.child(j)
                s = leaf.data(0, Qt.ItemDataRole.UserRole)
                hay = self._haystack(s, group_label)
                match = all(t in hay for t in terms)  # all() of [] is True
                leaf.setHidden(not match)
                visible += match
            group_item.setHidden(visible == 0)
            if terms and visible:
                group_item.setExpanded(True)
            any_match = any_match or visible > 0

        # Tint the box when a non-empty filter matches nothing.
        self.filter.setStyleSheet(
            "" if (any_match or not terms) else "color:#e88")

    def _open_from_item(self, item: QTreeWidgetItem, _col: int = 0):
        s = item.data(0, Qt.ItemDataRole.UserRole)
        if not isinstance(s, DeviceSession):
            return
        # Collapse a double-click (two itemActivated signals on macOS) into one
        # open. Intentional re-opens are seconds apart and pass the window.
        last_item, last_t = self._last_open
        now = time.monotonic()
        if item is last_item and (now - last_t) < 0.5:
            return
        self._last_open = (item, now)
        self.open_session(s)

    def open_session(self, session: DeviceSession):
        tab = HudTab(session, self.servers, self._resolve_identity)
        if tab.cancelled:
            tab.shutdown()
            tab.deleteLater()
            return
        tab.apply_zoom(self._zoom)   # inherit the current zoom level
        idx = self.tabs.addTab(tab, f"{session.name} · {session.vendor}")
        self.tabs.setCurrentIndex(idx)

    # ---- context menu + CRUD ----
    def _tree_menu(self, pos):
        item = self.tree.itemAt(pos)
        menu = QMenu(self)
        data = item.data(0, Qt.ItemDataRole.UserRole) if item else None

        if isinstance(data, DeviceSession):
            menu.addAction("Connect", lambda: self.open_session(data))
            menu.addSeparator()
            menu.addAction("Edit…", lambda: self._edit_session(data))
            menu.addAction("Duplicate", lambda: self._duplicate_session(data))
            menu.addAction("Delete", lambda: self._delete_session(data))
            menu.addSeparator()
            menu.addAction("New session…",
                           lambda: self._new_session(data.group))
            menu.addAction("New folder…", lambda: self._new_group())
        elif isinstance(data, tuple) and data[0] == "group":
            group = data[1]
            menu.addAction("New session in folder…",
                           lambda: self._new_session(group))
            menu.addAction("Rename folder…", lambda: self._rename_group(group))
            menu.addAction("Delete folder", lambda: self._delete_group(group))
            menu.addSeparator()
            menu.addAction("New folder…", lambda: self._new_group())
        else:
            menu.addAction("New session…", lambda: self._new_session())
            menu.addAction("New folder…", lambda: self._new_group())

        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def _new_session(self, group: str | None = None):
        dlg = SessionEditDialog(None, self.sessions.groups(), self.store, self)
        if group:
            dlg.group.setCurrentText(group)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.sessions.add(dlg.get_session())
            self._persist()
            self._refresh_tree()

    def _new_group(self):
        name, ok = QInputDialog.getText(self, "New folder", "Folder name:")
        if not (ok and name.strip()):
            return
        if not self.sessions.add_group(name.strip()):
            QMessageBox.information(
                self, "Folder exists",
                f"A folder named '{name.strip()}' already exists.")
            return
        self._persist()
        self._refresh_tree()

    def _edit_session(self, session: DeviceSession):
        dlg = SessionEditDialog(session, self.sessions.groups(), self.store, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            dlg.get_session()          # mutates `session` in place
            self.sessions.mark_dirty()
            self._persist()
            self._refresh_tree()

    def _duplicate_session(self, session: DeviceSession):
        self.sessions.duplicate(session)
        self._persist()
        self._refresh_tree()

    def _delete_session(self, session: DeviceSession):
        if QMessageBox.question(
                self, "Delete session",
                f"Delete '{session.name}' ({session.host})?") \
                != QMessageBox.StandardButton.Yes:
            return
        self.sessions.remove(session)
        self._persist()
        self._refresh_tree()

    def _rename_group(self, group: str):
        new, ok = QInputDialog.getText(self, "Rename group", "Group name:",
                                       text=group)
        if ok and new.strip() and new.strip() != group:
            self.sessions.rename_group(group, new.strip())
            self._persist()
            self._refresh_tree()

    def _delete_group(self, group: str):
        n = sum(1 for s in self.sessions.sessions
                if (s.group or "Ungrouped") == group)
        msg = (f"Delete empty folder '{group}'?" if n == 0
               else f"Delete folder '{group}' and its {n} session(s)?")
        if QMessageBox.question(self, "Delete folder", msg) \
                != QMessageBox.StandardButton.Yes:
            return
        self.sessions.remove_group(group)
        self._persist()
        self._refresh_tree()

    def _resolve_identity(self, session: DeviceSession):
        """Decide how a session authenticates. Runs on the UI thread so prompts
        and the vault unlock can be modal.

        The session's `credential` field selects the mode:
          "@prompt"  -> always ask at connect (ConnectAuthDialog).
          "@vendor"  -> let the server authenticate from its vendor yaml
                        (the page autoconnects; the only in-page auth path).
          "<name>"   -> a pinned vault credential (vault required).
          ""         -> auto: a host/tag/default vault match if the vault is
                        unlocked, else an inline secret on the session, else
                        prompt. Never silently vendor-defaults -- a connect with
                        nothing to authenticate with asks rather than failing in
                        the page.

        Returning None means the vendor-default page path; everything else is
        established by the wrapper and test_connect'd, so failures surface as the
        tab's error splash rather than only in the console.
        """
        cred = session.credential

        # Explicit vendor default.
        if cred == "@vendor":
            return None

        # Pinned vault credential (any non-empty value that isn't a sentinel).
        if cred and not cred.startswith("@"):
            if not ensure_unlocked(self.store, self):
                raise IdentityError(
                    f"Vault is locked — can't use credential '{cred}' "
                    f"for {session.host}.")
            ident = self.resolver.resolve(
                session.host, credential_name=cred,
                tags=session.tags, legacy_ssh=session.legacy_ssh)
            if ident is None:
                raise IdentityError(f"Credential '{cred}' is not in the vault.")
            return ident

        # "@prompt" forces the prompt; "" tries to auto-resolve first.
        if cred != "@prompt":
            # Auto: an unlocked vault may match by host/tag/default.
            if self.store.is_initialized() and self.store.is_unlocked:
                ident = self.resolver.resolve(
                    session.host, tags=session.tags, legacy_ssh=session.legacy_ssh)
                if ident is not None:
                    return ident
            # Inline secret on the session (a key *file* is read into key_text).
            if session.key_file:
                path = Path(session.key_file).expanduser()
                if not path.is_file():
                    raise IdentityError(f"Key file not found: {path}")
                return ResolvedIdentity(
                    username=session.username, key_text=path.read_text(),
                    use_keys=True, legacy_ssh=session.legacy_ssh,
                    source="inline-key")
            if session.password:
                return ResolvedIdentity(
                    username=session.username, password=session.password,
                    use_keys=False, legacy_ssh=session.legacy_ssh,
                    source="inline-pw")

        # Nothing to authenticate with (or "@prompt"): ask at connect.
        dlg = ConnectAuthDialog(session.host, session.username, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            raise ConnectCancelled
        data = dlg.identity()
        return ResolvedIdentity(
            username=data["username"],
            password=data.get("password"),
            key_text=data.get("key_text"),
            use_keys=bool(data.get("key_text")),
            legacy_ssh=session.legacy_ssh, source="prompt")

    # ---- tab close: single, bulk, and the bar context menu ----
    def _tab_menu(self, pos):
        """Right-click on the tab bar: close this tab, the others, the ones to
        its right, or all. Built around the tab under the cursor; tabAt() is -1
        on empty bar space, where only Close All is meaningful."""
        bar = self.tabs.tabBar()
        index = bar.tabAt(pos)
        count = self.tabs.count()
        menu = QMenu(self)
        if index >= 0:
            menu.addAction("Close", lambda: self._close_tab(index))
            a_others = menu.addAction(
                "Close Others", lambda: self._close_others(index))
            a_others.setEnabled(count > 1)
            a_right = menu.addAction(
                "Close to the Right", lambda: self._close_to_right(index))
            a_right.setEnabled(index < count - 1)
            menu.addSeparator()
        a_all = menu.addAction("Close All", self._close_all_tabs)
        a_all.setEnabled(count > 0)
        menu.exec(bar.mapToGlobal(pos))

    def _close_widget(self, w):
        """Tear down one tab by widget reference. Bulk closers go through this
        rather than by index because removeTab() shifts every later index, so
        they snapshot the widgets first and close by identity."""
        idx = self.tabs.indexOf(w)
        if idx != -1:
            self.tabs.removeTab(idx)
        if w:
            if hasattr(w, "shutdown"):
                w.shutdown()
            w.deleteLater()

    def _close_tab(self, index: int):
        self._close_widget(self.tabs.widget(index))

    def _close_others(self, keep_index: int):
        keep = self.tabs.widget(keep_index)
        for w in [self.tabs.widget(i) for i in range(self.tabs.count())]:
            if w is not keep:
                self._close_widget(w)

    def _close_to_right(self, index: int):
        for w in [self.tabs.widget(i)
                  for i in range(index + 1, self.tabs.count())]:
            self._close_widget(w)

    def _close_all_tabs(self):
        for w in [self.tabs.widget(i) for i in range(self.tabs.count())]:
            self._close_widget(w)

    # ---- UI-state persistence (geometry / splitter / zoom / last file) ----
    def _remember_file(self, path: str, kind: str):
        """Record the file to reopen next launch. Written immediately (not just
        on close) so an unclean exit still remembers it."""
        self._last_file = (path, kind)
        self.settings.setValue("session/last_path", path)
        self.settings.setValue("session/last_kind", kind)

    def _restore_ui_state(self):
        """Re-apply window geometry, splitter sizes, and HUD zoom saved at last
        exit. Geometry/splitter are opaque QByteArray blobs; zoom is clamped in
        case the saved value predates a change to ZOOM_LEVELS. The session file
        itself is reopened in main(), before the window exists."""
        geo = self.settings.value("ui/geometry")
        if geo is not None:
            self.restoreGeometry(geo)
        state = self.settings.value("ui/splitter")
        if state is not None:
            self.split.restoreState(state)
        z = self.settings.value("ui/zoom", 1.0, type=float)
        self._zoom = max(ZOOM_LEVELS[0], min(ZOOM_LEVELS[-1], z))
        self._zoom_readout.setText(f"Current zoom: {round(self._zoom * 100)}%")

    def _save_ui_state(self):
        self.settings.setValue("ui/geometry", self.saveGeometry())
        self.settings.setValue("ui/splitter", self.split.saveState())
        self.settings.setValue("ui/zoom", self._zoom)
        path, kind = self._last_file
        if path:
            self.settings.setValue("session/last_path", path)
            self.settings.setValue("session/last_kind", kind or "termtels")
        else:
            # No file open: don't leave a stale path to reopen.
            self.settings.remove("session/last_path")
            self.settings.remove("session/last_kind")

    def closeEvent(self, event):
        if not self._maybe_save_changes():
            event.ignore()
            return
        self._save_ui_state()
        self.servers.stop_all()
        super().closeEvent(event)

def apply_dark(app):
    app.setStyle("Fusion")
    p = QPalette()
    base    = QColor(30, 30, 30)
    alt     = QColor(45, 45, 45)
    text    = QColor(220, 220, 220)
    disabled= QColor(127, 127, 127)
    p.setColor(QPalette.ColorRole.Window, base)
    p.setColor(QPalette.ColorRole.WindowText, text)
    p.setColor(QPalette.ColorRole.Base, QColor(20, 20, 20))
    p.setColor(QPalette.ColorRole.AlternateBase, alt)
    p.setColor(QPalette.ColorRole.Text, text)
    p.setColor(QPalette.ColorRole.Button, alt)
    p.setColor(QPalette.ColorRole.ButtonText, text)
    p.setColor(QPalette.ColorRole.ToolTipBase, base)
    p.setColor(QPalette.ColorRole.ToolTipText, text)
    p.setColor(QPalette.ColorRole.Highlight, QColor(0, 120, 60))
    p.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
    p.setColor(QPalette.ColorRole.Link, QColor(0, 200, 120))
    for role in (QPalette.ColorRole.Text, QPalette.ColorRole.WindowText,
                 QPalette.ColorRole.ButtonText):
        p.setColor(QPalette.ColorGroup.Disabled, role, disabled)
    app.setPalette(p)


def _restore_last_session(store: SessionStore, settings: QSettings):
    """Reopen the file that was open at last exit, when no file is given on the
    CLI. A "devices" import is re-imported (path stays None so a devices.yaml is
    never silently rewritten); a "termtels" file loads as the save target,
    exactly as the File-menu loaders do. Returns the (path, kind) reopened, or
    (None, None) if nothing was stored or the file no longer exists."""
    path = settings.value("session/last_path", "", type=str)
    kind = settings.value("session/last_kind", "termtels", type=str)
    if not path or not Path(path).is_file():
        return (None, None)
    try:
        if kind == "devices":
            store.adopt(load_nethuds_devices(path))
        else:
            store.load(path)
    except Exception as e:
        logger.warning("Could not reopen last session file %s: %s", path, e)
        return (None, None)
    logger.info("Reopened last session file: %s", path)
    return (path, kind)


def main():
    ap = argparse.ArgumentParser(prog="nethuds-desktop")
    ap.add_argument("--session-file", help="termtels session YAML to load on start")
    ap.add_argument("--devices", help="nethuds devices.yaml to load on start")
    ap.add_argument(
        "--remote-debug", nargs="?", const=9222, type=int, metavar="PORT",
        help="enable QtWebEngine remote debugging (default port 9222). "
             "Open a Chromium-based browser at http://127.0.0.1:<PORT>.",
    )
    ap.add_argument(
        "--scale", type=float, metavar="FACTOR",
        help="force a global UI scale factor (e.g. 1.25, 1.5) when a display's "
             "auto-detected high-DPI scaling is wrong. Overrides QT_SCALE_FACTOR "
             "and any saved ui/scale. Use 0 to clear a saved scale.",
    )
    args = ap.parse_args()

    # Must be set before QtWebEngine initialises (i.e. before QApplication).
    if args.remote_debug:
        os.environ["QTWEBENGINE_REMOTE_DEBUGGING"] = str(args.remote_debug)
        logger.info("Remote debugging on http://127.0.0.1:%s "
                    "(open in a Chromium-based browser)", args.remote_debug)

    settings = QSettings(SETTINGS_ORG, SETTINGS_APP)
    session_store = SessionStore()
    initial_file = (None, None)   # (path, kind) carried into MainWindow for restart persistence
    try:
        if args.session_file:
            session_store.load(args.session_file)
            initial_file = (args.session_file, "termtels")
        elif args.devices:
            session_store.adopt(load_nethuds_devices(args.devices))
            initial_file = (args.devices, "devices")
        else:
            # No file on the CLI: reopen the one from last session, if any.
            initial_file = _restore_last_session(session_store, settings)
    except Exception as e:
        logger.error("Failed to load sessions: %s", e)

    # ---- High-DPI ----
    # Qt6 scales to the device pixel ratio automatically (the Qt5
    # AA_EnableHighDpiScaling / AA_UseHighDpiPixmaps attributes are no-ops now),
    # so the chrome and the QWebEngineView HUD are already high-DPI. The one
    # default worth changing is the rounding policy: PassThrough keeps fractional
    # display scales (125 % / 150 % / 175 % on Windows & Linux 4K panels) crisp
    # instead of rounding them to the nearest integer. No effect on macOS Retina
    # (integer 2x). Must be set before QApplication is constructed.
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)

    # Manual override for a display where auto-detection is wrong. Precedence:
    # --scale flag > saved ui/scale > Qt auto-detection. QT_SCALE_FACTOR is the
    # Qt-level knob and must be in the environment before QApplication exists.
    # --scale 0 clears a previously saved value and falls back to auto.
    saved_scale = settings.value("ui/scale", 0.0, type=float)
    scale = args.scale if args.scale is not None else saved_scale
    if args.scale is not None:
        if args.scale and args.scale > 0:
            settings.setValue("ui/scale", args.scale)   # persist as a real setting
        else:
            settings.remove("ui/scale")
    if scale and scale > 0:
        os.environ["QT_SCALE_FACTOR"] = str(scale)
        logger.info("Forcing UI scale factor %.3g (QT_SCALE_FACTOR)", scale)

    # Recommended for QtWebEngine; must be set before QApplication.
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts)
    app = QApplication(sys.argv)
    apply_dark(app)
    win = MainWindow(session_store, initial_file)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()