"""
Qt dialogs for the nethuds desktop wrapper.

For now this is the vault gate: unlock an existing vault, or create one on
first use. The full credential-manager UI (list/add/edit) lands alongside the
editable session tree; this file deliberately holds only what the connect path
needs so key-auth works end to end without the larger manager.
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFormLayout, QFrame, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from .sessions import DeviceSession
from .vault import CredentialStore, StoredCredential

# Friendly label -> netmiko device_type. The HUD a session routes to is derived
# from this (arista_eos -> arista HUD, etc.), so the editor offers the canonical
# set rather than free text.
DEVICE_TYPES: list[tuple[str, str]] = [
    ("Arista EOS", "arista_eos"),
    ("Juniper Junos", "juniper_junos"),
    ("Cisco IOS", "cisco_ios"),
    ("Cisco IOS-XE", "cisco_xe"),
    ("Cisco NX-OS", "cisco_nxos"),
    ("Cisco IOS-XR", "cisco_xr"),
    ("Linux", "linux"),
]
_CRED_PROMPT = "(prompt at connect)"
_CRED_NONE = "(none — vault match, else prompt)"
_CRED_VENDOR = "(vendor default — server config)"


class VaultUnlockDialog(QDialog):
    """Prompt for the master password. If the vault does not exist yet, switch
    to a create-with-confirm flow so a first connect can still proceed."""

    def __init__(self, store: CredentialStore, parent=None):
        super().__init__(parent)
        self.store = store
        self._initializing = not store.is_initialized()
        self.setWindowTitle("Create vault" if self._initializing else "Unlock vault")
        self.setMinimumWidth(360)

        layout = QVBoxLayout(self)
        intro = QLabel(
            "No credential vault yet — set a master password to create one."
            if self._initializing else
            "Enter the master password to unlock stored credentials."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        form = QFormLayout()
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Master password", self.pw)
        self.confirm = None
        if self._initializing:
            self.confirm = QLineEdit()
            self.confirm.setEchoMode(QLineEdit.EchoMode.Password)
            form.addRow("Confirm", self.confirm)
        layout.addLayout(form)

        self.status = QLabel("")
        self.status.setStyleSheet("color:#e33")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.pw.setFocus()

    def _accept(self):
        pw = self.pw.text()
        if not pw:
            self.status.setText("Password is required.")
            return
        if self._initializing:
            if pw != self.confirm.text():
                self.status.setText("Passwords do not match.")
                return
            try:
                self.store.init_vault(pw)
            except Exception as e:  # pragma: no cover - defensive
                self.status.setText(f"Could not create vault: {e}")
                return
        if not self.store.unlock(pw):
            self.status.setText("Wrong master password.")
            self.pw.selectAll()
            self.pw.setFocus()
            return
        self.accept()


def ensure_unlocked(store: CredentialStore, parent=None) -> bool:
    """Return True if the vault is unlocked, prompting once if needed.

    Safe to call on every connect: a no-op when already unlocked.
    """
    if store.is_unlocked:
        return True
    dlg = VaultUnlockDialog(store, parent)
    return dlg.exec() == QDialog.DialogCode.Accepted and store.is_unlocked


class SessionEditDialog(QDialog):
    """Add or edit one DeviceSession.

    Credentials are offered by name from the vault (its metadata list works even
    while locked), plus a "(none)" option for inline/vendor-default auth. Group
    is an editable combo so a session can join an existing group or start a new
    one. On accept, get_session() returns a new DeviceSession, or applies the
    edits to the session passed in.
    """

    def __init__(self, session: DeviceSession | None = None,
                 groups: list[str] | None = None,
                 store: CredentialStore | None = None, parent=None):
        super().__init__(parent)
        self._editing = session is not None
        self.setWindowTitle("Edit session" if self._editing else "New session")
        self.setMinimumWidth(420)
        s = session or DeviceSession(name="", host="")

        form = QFormLayout()

        self.name = QLineEdit(s.name)
        form.addRow("Name", self.name)

        self.host = QLineEdit(s.host)
        self.host.setPlaceholderText("IP or hostname")
        form.addRow("Host", self.host)

        self.dtype = QComboBox()
        for label, dt in DEVICE_TYPES:
            self.dtype.addItem(label, dt)
        idx = next((i for i, (_, dt) in enumerate(DEVICE_TYPES)
                    if dt == s.device_type), len(DEVICE_TYPES) - 1)
        self.dtype.setCurrentIndex(idx)
        form.addRow("Device type", self.dtype)

        self.group = QComboBox()
        self.group.setEditable(True)
        for g in (groups or []):
            self.group.addItem(g)
        self.group.setCurrentText(s.group or (groups[0] if groups else ""))
        form.addRow("Group", self.group)

        self.credential = QComboBox()
        self.credential.addItem(_CRED_PROMPT, "@prompt")
        self.credential.addItem(_CRED_NONE, "")
        cred_names = []
        if store is not None and store.is_initialized():
            try:
                cred_names = [c.name for c in store.list_credentials()]
            except Exception:
                cred_names = []
        for name in cred_names:
            self.credential.addItem(name, name)
        if s.credential and not s.credential.startswith("@") \
                and s.credential not in cred_names:
            # Preserve a pinned credential even if the vault can't be read now.
            self.credential.addItem(f"{s.credential} (not in vault)", s.credential)
        self.credential.addItem(_CRED_VENDOR, "@vendor")
        self._select_data(self.credential, s.credential)
        self.credential.setToolTip(
            "How this session authenticates:\n"
            "• a vault credential name — use that stored credential\n"
            "• prompt at connect — always ask for username + password/key\n"
            "• none — use a matching vault credential if unlocked, else prompt\n"
            "• vendor default — the HUD server authenticates from its own yaml")
        form.addRow("Credential", self.credential)

        self.username = QLineEdit(s.username)
        self.username.setPlaceholderText("only if no credential is set")
        form.addRow("Username", self.username)

        self.tags = QLineEdit(", ".join(s.tags))
        self.tags.setPlaceholderText("comma-separated, e.g. lab, spine")
        form.addRow("Tags", self.tags)

        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(s.port or 22)
        form.addRow("SSH port", self.port)

        self.legacy = QCheckBox("Legacy SSH (old KEX / host-key algorithms)")
        self.legacy.setChecked(s.legacy_ssh)
        form.addRow("", self.legacy)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        self.status = QLabel("")
        self.status.setStyleSheet("color:#e33")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._session = session
        self.name.setFocus()

    @staticmethod
    def _select_data(combo: QComboBox, data):
        for i in range(combo.count()):
            if combo.itemData(i) == data:
                combo.setCurrentIndex(i)
                return

    def _accept(self):
        if not self.name.text().strip():
            self.status.setText("Name is required.")
            return
        if not self.host.text().strip():
            self.status.setText("Host is required.")
            return
        self.accept()

    def get_session(self) -> DeviceSession:
        """Build/apply the edited values. Mutates the existing session in place
        when editing (so tree-item references stay valid), else returns a new one."""
        tags = [t.strip() for t in self.tags.text().split(",") if t.strip()]
        cred = self.credential.currentData() or ""
        values = dict(
            name=self.name.text().strip(),
            host=self.host.text().strip(),
            device_type=self.dtype.currentData(),
            group=self.group.currentText().strip(),
            credential=cred,
            username=self.username.text().strip(),
            tags=tags,
            port=self.port.value(),
            legacy_ssh=self.legacy.isChecked(),
        )
        if self._session is not None:
            for k, v in values.items():
                setattr(self._session, k, v)
            return self._session
        return DeviceSession(**values)


class ConnectAuthDialog(QDialog):
    """Prompt for a secret at connect time for an inline session (no stored
    credential). Username is pre-filled but editable; the user supplies a
    password or picks a key file whose CONTENTS are read (never a path, since
    that's all the HUD servers accept). Nothing entered here is persisted."""

    def __init__(self, host: str, username: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Authenticate to {host}")
        self.setMinimumWidth(420)
        self._key_text: str | None = None

        form = QFormLayout()
        self.username = QLineEdit(username)
        form.addRow("Username", self.username)

        self.method = QComboBox()
        self.method.addItem("Password", "password")
        self.method.addItem("SSH key file", "key")
        self.method.currentIndexChanged.connect(self._apply_mode)
        form.addRow("Method", self.method)

        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self._pw_row = self.password
        form.addRow("Password", self.password)

        # key row: a read-only path display + Browse button
        from PyQt6.QtWidgets import QHBoxLayout, QPushButton, QWidget
        self.key_path = QLineEdit()
        self.key_path.setReadOnly(True)
        self.key_path.setPlaceholderText("choose a private key file…")
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse_key)
        row = QWidget()
        hl = QHBoxLayout(row)
        hl.setContentsMargins(0, 0, 0, 0)
        hl.addWidget(self.key_path)
        hl.addWidget(browse)
        self._key_widget = row
        form.addRow("Key file", row)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        self.status = QLabel("")
        self.status.setStyleSheet("color:#e33")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._apply_mode()
        (self.password if self.method.currentData() == "password"
         else self.username).setFocus()

    def _apply_mode(self):
        is_pw = self.method.currentData() == "password"
        self.password.setVisible(is_pw)
        self._key_widget.setVisible(not is_pw)
        # Toggle the form-row labels too.
        form: QFormLayout = self.layout().itemAt(0).layout()
        for w in (self.password, self._key_widget):
            lbl = form.labelForField(w)
            if lbl:
                lbl.setVisible(w.isVisible())

    def _browse_key(self):
        from PyQt6.QtWidgets import QFileDialog
        import os
        start = os.path.expanduser("~/.ssh")
        path, _ = QFileDialog.getOpenFileName(self, "Select private key", start)
        if path:
            try:
                self._key_text = open(path).read()
                self.key_path.setText(path)
            except Exception as e:
                self.status.setText(f"Could not read key: {e}")
                self._key_text = None

    def _accept(self):
        if not self.username.text().strip():
            self.status.setText("Username is required.")
            return
        if self.method.currentData() == "password":
            if not self.password.text():
                self.status.setText("Password is required.")
                return
        elif not self._key_text:
            self.status.setText("Choose a key file.")
            return
        self.accept()

    def identity(self) -> dict:
        """Return {'username', and one of 'password' / 'key_text'}."""
        out = {"username": self.username.text().strip()}
        if self.method.currentData() == "password":
            out["password"] = self.password.text()
        else:
            out["key_text"] = self._key_text
        return out

# ---------------------------------------------------------------------------
# Credential manager
#
# The Qt front door to the vault that retires nhd.vaultctl for day-to-day use:
# list / add / edit / delete / set-default, plus rename and username-change in
# place (the two edits the CLI can't do, since vaultctl has no update path).
#
# Capability boundaries mirror CredentialStore exactly:
#   * list / remove / set-default work while LOCKED (metadata-only or no-secret
#     ops), so the manager stays useful before an unlock.
#   * add / edit / rename touch ciphertext and REQUIRE an unlocked vault, so
#     those actions are disabled until the vault is unlocked.
# Secrets are only ever decrypted into the editor when the vault is unlocked,
# which is the same gate the connect path uses.
# ---------------------------------------------------------------------------

_ACCENT = "#00c878"   # the app's link-green, reused for the default marker
_ERROR = "#e33"       # matches the other dialogs' status labels


def _key_looks_encrypted(key_text: str) -> bool:
    """True if a pasted/loaded private key looks passphrase-protected. The HUD
    server can't forward a passphrase to paramiko, so we warn (don't block) --
    same posture as vaultctl's add path."""
    if not key_text:
        return False
    head = key_text.strip().splitlines()
    if not head:
        return False
    first = head[0]
    return "ENCRYPTED" in first or any(
        ln.startswith("Proc-Type:") and "ENCRYPTED" in ln for ln in head[:5])


class CredentialEditDialog(QDialog):
    """Add a new credential, or edit an existing one in place.

    On *edit*, the dialog is handed a fully-resolved StoredCredential (secrets
    decrypted -- only possible with the vault unlocked) and pre-fills every
    field, so what you see is exactly what will be stored. Clearing the password
    or key field removes that secret. A credential must keep at least one secret,
    matching the invariant vaultctl enforces at add time.

    Name and username are both editable here: a changed name becomes a rename,
    a changed username an update -- the two things the CLI front door can't do.
    """

    def __init__(self, store: CredentialStore,
                 credential: StoredCredential | None = None, parent=None):
        super().__init__(parent)
        self.store = store
        self._editing = credential is not None
        self._original_name = credential.name if credential else None
        self.setWindowTitle("Edit credential" if self._editing else "New credential")
        self.setMinimumWidth(480)
        c = credential

        form = QFormLayout()

        self.name = QLineEdit(c.name if c else "")
        self.name.setPlaceholderText("vault entry name, e.g. edge-key")
        form.addRow("Name", self.name)

        self.username = QLineEdit(c.username if c else "")
        self.username.setPlaceholderText("ssh username")
        form.addRow("Username", self.username)

        # --- password (with reveal toggle) ---
        self.password = QLineEdit(c.password if (c and c.password) else "")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("leave blank for none / key-only")
        show_pw = QPushButton("Show")
        show_pw.setCheckable(True)
        show_pw.setFixedWidth(56)
        show_pw.toggled.connect(
            lambda on: (self.password.setEchoMode(
                QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password),
                show_pw.setText("Hide" if on else "Show")))
        pw_row = _row(self.password, show_pw)
        form.addRow("Password", pw_row)

        # --- ssh private key body + load/clear ---
        self.key = QPlainTextEdit(c.ssh_key if (c and c.ssh_key) else "")
        self.key.setPlaceholderText(
            "paste a private key, or Load from file… (the key BODY is stored, "
            "never a path)")
        mono = QFont("Menlo, Consolas, monospace")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        mono.setPointSize(9)
        self.key.setFont(mono)
        self.key.setFixedHeight(110)
        self.key.textChanged.connect(self._check_key)
        load = QPushButton("Load from file…")
        load.clicked.connect(self._load_key)
        clear = QPushButton("Clear")
        clear.clicked.connect(self.key.clear)
        key_box = QVBoxLayout()
        key_box.setContentsMargins(0, 0, 0, 0)
        key_box.addWidget(self.key)
        key_box.addWidget(_row(load, clear, stretch_last=False))
        key_wrap = QWidget()
        key_wrap.setLayout(key_box)
        form.addRow("SSH key", key_wrap)

        self.passphrase = QLineEdit(
            c.ssh_key_passphrase if (c and c.ssh_key_passphrase) else "")
        self.passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase.setPlaceholderText(
            "stored, but the HUD server can't forward it to paramiko")
        form.addRow("Key passphrase", self.passphrase)

        note = QLabel(
            "When both a password and a key are present, key auth wins "
            "(matches the resolver and the HUD server).")
        note.setWordWrap(True)
        note.setStyleSheet("color:#999")
        form.addRow("", note)

        # --- resolution rules ---
        self.hosts = QLineEdit(", ".join(c.match_hosts) if c else "")
        self.hosts.setPlaceholderText("comma-separated globs, e.g. border*, *.site1")
        form.addRow("Match hosts", self.hosts)

        self.tags = QLineEdit(", ".join(c.match_tags) if c else "")
        self.tags.setPlaceholderText("comma-separated, e.g. lab, spine")
        form.addRow("Match tags", self.tags)

        self.is_default = QCheckBox("Catch-all default (used when nothing else matches)")
        self.is_default.setChecked(bool(c.is_default) if c else False)
        form.addRow("", self.is_default)

        layout = QVBoxLayout(self)
        layout.addLayout(form)

        self.status = QLabel("")
        self.status.setStyleSheet(f"color:{_ERROR}")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.name.setFocus()

    # -- key helpers --
    def _load_key(self):
        import os
        start = os.path.expanduser("~/.ssh")
        path, _ = QFileDialog.getOpenFileName(self, "Select private key", start)
        if not path:
            return
        try:
            self.key.setPlainText(Path(path).read_text())
        except Exception as e:
            self.status.setText(f"Could not read key: {e}")

    def _check_key(self):
        # Non-blocking advisory, mirroring vaultctl's warning.
        if _key_looks_encrypted(self.key.toPlainText()):
            self.status.setStyleSheet("color:#d8a000")
            self.status.setText(
                "This key looks passphrase-encrypted — the HUD server can't "
                "supply a passphrase to paramiko. Use a passphrase-less key.")
        elif self.status.text().startswith("This key looks"):
            self.status.setText("")

    # -- accept / values --
    def _accept(self):
        if not self.name.text().strip():
            self._err("Name is required."); return
        if not self.username.text().strip():
            self._err("Username is required."); return
        if not self.password.text() and not self.key.toPlainText().strip():
            self._err("A credential needs a secret — set a password and/or a key.")
            return
        # name collision check on add, or on rename to an existing name
        new_name = self.name.text().strip()
        if new_name != self._original_name:
            try:
                if self.store.get_credential(new_name) is not None:
                    self._err(f"A credential named {new_name!r} already exists.")
                    return
            except Exception:
                pass  # locked: the manager won't have enabled add/edit anyway
        self.accept()

    def _err(self, msg: str):
        self.status.setStyleSheet(f"color:{_ERROR}")
        self.status.setText(msg)

    def values(self) -> dict:
        """Field values ready for add_credential / update_credential. Empty
        password/key become None so the store clears them."""
        return dict(
            name=self.name.text().strip(),
            username=self.username.text().strip(),
            password=self.password.text() or None,
            ssh_key=self.key.toPlainText().strip() or None,
            ssh_key_passphrase=self.passphrase.text() or None,
            match_hosts=[h.strip() for h in self.hosts.text().split(",") if h.strip()],
            match_tags=[t.strip() for t in self.tags.text().split(",") if t.strip()],
            is_default=self.is_default.isChecked(),
        )


class ChangeMasterPasswordDialog(QDialog):
    """Re-key the vault: prompts for the current and new master password and
    calls change_master_password, which re-encrypts every secret. Works from a
    locked vault since it verifies the current password itself."""

    def __init__(self, store: CredentialStore, parent=None):
        super().__init__(parent)
        self.store = store
        self.setWindowTitle("Change master password")
        self.setMinimumWidth(380)

        form = QFormLayout()
        self.old = QLineEdit(); self.old.setEchoMode(QLineEdit.EchoMode.Password)
        self.new = QLineEdit(); self.new.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm = QLineEdit(); self.confirm.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Current password", self.old)
        form.addRow("New password", self.new)
        form.addRow("Confirm new", self.confirm)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        self.status = QLabel(""); self.status.setStyleSheet(f"color:{_ERROR}")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.old.setFocus()

    def _accept(self):
        if not self.new.text():
            self.status.setText("New password is required."); return
        if self.new.text() != self.confirm.text():
            self.status.setText("New passwords do not match."); return
        if not self.store.change_master_password(self.old.text(), self.new.text()):
            self.status.setText("Current password is incorrect.")
            self.old.selectAll(); self.old.setFocus(); return
        self.accept()


class CredentialManagerDialog(QDialog):
    """Vault → Manage credentials… — the CLI's replacement for daily use.

    Opens against whatever lock state the vault is in. The metadata listing
    works locked; an inline banner offers to unlock, and the secret-touching
    actions (Add / Edit) stay disabled until it is. Delete and Set default work
    locked, so they stay live."""

    _COLS = ["Name", "Username", "Auth", "Match hosts", "Tags", "Default"]

    def __init__(self, store: CredentialStore, parent=None):
        super().__init__(parent)
        self.store = store
        self.setWindowTitle("Manage credentials")
        self.resize(720, 420)

        root = QVBoxLayout(self)

        # lock-state banner
        self.banner = QFrame()
        self.banner.setFrameShape(QFrame.Shape.StyledPanel)
        b = QHBoxLayout(self.banner)
        b.setContentsMargins(10, 6, 10, 6)
        self.banner_label = QLabel("")
        self.banner_label.setWordWrap(True)
        self.unlock_btn = QPushButton("Unlock…")
        self.unlock_btn.clicked.connect(self._unlock)
        b.addWidget(self.banner_label, 1)
        b.addWidget(self.unlock_btn, 0)
        root.addWidget(self.banner)

        # table
        self.table = QTableWidget(0, len(self._COLS))
        self.table.setHorizontalHeaderLabels(self._COLS)
        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.itemSelectionChanged.connect(self._sync_buttons)
        self.table.itemDoubleClicked.connect(lambda *_: self._edit())
        root.addWidget(self.table, 1)

        # actions
        bar = QHBoxLayout()
        self.add_btn = QPushButton("Add…");           self.add_btn.clicked.connect(self._add)
        self.edit_btn = QPushButton("Edit…");          self.edit_btn.clicked.connect(self._edit)
        self.del_btn = QPushButton("Delete");          self.del_btn.clicked.connect(self._delete)
        self.def_btn = QPushButton("Set default");     self.def_btn.clicked.connect(self._set_default)
        self.rekey_btn = QPushButton("Change master…"); self.rekey_btn.clicked.connect(self._rekey)
        for w in (self.add_btn, self.edit_btn, self.del_btn, self.def_btn):
            bar.addWidget(w)
        bar.addStretch(1)
        bar.addWidget(self.rekey_btn)
        root.addLayout(bar)

        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.reject)
        close.button(QDialogButtonBox.StandardButton.Close).clicked.connect(self.accept)
        root.addWidget(close)

        self._reload()

    # -- state --
    def _unlocked(self) -> bool:
        return self.store.is_initialized() and self.store.is_unlocked

    def _selected_name(self) -> str | None:
        items = self.table.selectedItems()
        if not items:
            return None
        return self.table.item(items[0].row(), 0).data(Qt.ItemDataRole.UserRole)

    def _reload(self):
        try:
            creds = self.store.list_credentials() if self.store.is_initialized() else []
        except Exception as e:
            creds = []
            QMessageBox.warning(self, "Vault", f"Could not read vault: {e}")
        self.table.setRowCount(0)
        for c in creds:
            row = self.table.rowCount()
            self.table.insertRow(row)
            auth = "/".join(
                ([("key" if c.ssh_key else "")] if c.ssh_key else []) +
                ([("pw" if c.password else "")] if c.password else [])) or "no-secret"
            cells = [
                c.name, c.username, auth,
                ", ".join(c.match_hosts) or "—",
                ", ".join(c.match_tags) or "—",
                "✓" if c.is_default else "",
            ]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, c.name)
                if col == 5 and c.is_default:
                    item.setForeground(QColor(_ACCENT))
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(row, col, item)
        self._sync_buttons()

    def _sync_buttons(self):
        unlocked = self._unlocked()
        initialized = self.store.is_initialized()
        has_sel = self._selected_name() is not None

        if not initialized:
            self.banner_label.setText(
                "No vault yet. Unlock to create one and add credentials.")
            self.banner.setVisible(True)
            self.unlock_btn.setVisible(True)
        elif not unlocked:
            self.banner_label.setText(
                "Vault is locked — showing names only. Unlock to add or edit "
                "credentials (delete and set-default work while locked).")
            self.banner.setVisible(True)
            self.unlock_btn.setVisible(True)
        else:
            self.banner.setVisible(False)

        self.add_btn.setEnabled(unlocked)
        self.edit_btn.setEnabled(unlocked and has_sel)
        self.del_btn.setEnabled(initialized and has_sel)
        self.def_btn.setEnabled(initialized and has_sel)
        self.rekey_btn.setEnabled(initialized)
        tip = "" if unlocked else "Unlock the vault to use this."
        self.add_btn.setToolTip(tip)
        self.edit_btn.setToolTip(tip)

    # -- actions --
    def _unlock(self):
        # Local import avoids a cycle and reuses the existing unlock/create flow.
        if ensure_unlocked(self.store, self):
            self._reload()

    def _add(self):
        if not self._unlocked():
            return
        dlg = CredentialEditDialog(self.store, None, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        v = dlg.values()
        try:
            self.store.add_credential(
                v["name"], v["username"], password=v["password"],
                ssh_key=v["ssh_key"], ssh_key_passphrase=v["ssh_key_passphrase"],
                match_hosts=v["match_hosts"], match_tags=v["match_tags"],
                is_default=v["is_default"])
        except Exception as e:
            QMessageBox.critical(self, "Add credential", f"Could not add: {e}")
            return
        self._reload()
        self._select(v["name"])

    def _edit(self):
        name = self._selected_name()
        if not name or not self._unlocked():
            return
        try:
            cred = self.store.get_credential(name)
        except Exception as e:
            QMessageBox.warning(self, "Edit credential", f"Could not read: {e}")
            return
        if cred is None:
            return
        dlg = CredentialEditDialog(self.store, cred, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        v = dlg.values()
        try:
            # Rename first (the CLI can't); update_credential keys off the name.
            target = name
            if v["name"] != name:
                if not self.store.rename_credential(name, v["name"]):
                    raise RuntimeError("rename failed")
                target = v["name"]
            self.store.update_credential(
                target, username=v["username"], password=v["password"],
                ssh_key=v["ssh_key"], ssh_key_passphrase=v["ssh_key_passphrase"],
                match_hosts=v["match_hosts"], match_tags=v["match_tags"],
                is_default=v["is_default"])
        except Exception as e:
            QMessageBox.critical(self, "Edit credential", f"Could not save: {e}")
            return
        self._reload()
        self._select(v["name"])

    def _delete(self):
        name = self._selected_name()
        if not name:
            return
        if QMessageBox.question(
                self, "Delete credential",
                f"Delete credential {name!r}? Sessions that pin it by name will "
                f"fall back to prompting at connect.") != QMessageBox.StandardButton.Yes:
            return
        try:
            self.store.remove_credential(name)
        except Exception as e:
            QMessageBox.critical(self, "Delete credential", f"Could not delete: {e}")
            return
        self._reload()

    def _set_default(self):
        name = self._selected_name()
        if not name:
            return
        try:
            self.store.set_default(name)
        except Exception as e:
            QMessageBox.critical(self, "Set default", f"Could not set default: {e}")
            return
        self._reload()
        self._select(name)

    def _rekey(self):
        dlg = ChangeMasterPasswordDialog(self.store, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            QMessageBox.information(self, "Vault", "Master password changed.")
            self._reload()

    # -- selection helper --
    def _select(self, name: str):
        for row in range(self.table.rowCount()):
            if self.table.item(row, 0).data(Qt.ItemDataRole.UserRole) == name:
                self.table.selectRow(row)
                return


def _row(*widgets, stretch_last: bool = True) -> QWidget:
    """Pack widgets into a horizontal, margin-free row widget for QFormLayout."""
    w = QWidget()
    hl = QHBoxLayout(w)
    hl.setContentsMargins(0, 0, 0, 0)
    for i, widget in enumerate(widgets):
        hl.addWidget(widget, 1 if (stretch_last and i == 0) else 0)
    return w


# ---------------------------------------------------------------------------
# About
# ---------------------------------------------------------------------------

GITHUB_URL = "https://github.com/scottpeterman/nhd"


class AboutDialog(QDialog):
    """Help → About: the logo up top, a one-line description, the project link.

    The logo is loaded from the package's assets/logo.svg and rendered with
    QSvgWidget so it stays crisp at any DPI and any display size. If the asset
    is missing or unreadable the dialog simply omits it rather than failing —
    the About box never hard-depends on a bundled file.
    """

    _LOGO_BOX = (320, 200)   # max (w, h) the logo is fit into, aspect-preserved

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About nethuds desktop")
        self.setMinimumWidth(440)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 16)

        logo = self._logo_widget()
        if logo is not None:
            layout.addWidget(logo, 0, Qt.AlignmentFlag.AlignHCenter)

        title = QLabel("nethuds desktop")
        tf = title.font()
        tf.setPointSize(16)
        tf.setBold(True)
        title.setFont(tf)
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(title)

        desc = QLabel(
            "A triage cockpit for network devices. Point it at a box you've "
            "never seen — nothing but an IP and credentials — and it renders "
            "that device's live health as a single HUD, read the same way "
            "across Arista, Juniper, Cisco IOS, and Linux. No prior "
            "instrumentation required; the only prerequisite is SSH access."
        )
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        desc.setStyleSheet("color:#bbb")
        layout.addWidget(desc)

        link = QLabel(f'<a href="{GITHUB_URL}">github.com/scottpeterman/nhd</a>')
        link.setOpenExternalLinks(True)
        link.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction)
        link.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        # The link colour follows the palette's Link role (the app's green).
        layout.addWidget(link)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.accept)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    @staticmethod
    def _logo_path() -> Path:
        return Path(__file__).resolve().parent / "assets" / "logo.svg"

    def _logo_widget(self):
        """A QSvgWidget showing the logo, sized to fit _LOGO_BOX with aspect
        preserved (scaled up or down as needed for a prominent but bounded
        display). Returns None if the asset or the Qt SVG module is unavailable.
        """
        path = self._logo_path()
        if not path.is_file():
            return None
        try:
            from PyQt6.QtSvgWidgets import QSvgWidget
            from PyQt6.QtSvg import QSvgRenderer
        except Exception:
            return None

        renderer = QSvgRenderer(str(path))
        if not renderer.isValid():
            return None
        size = renderer.defaultSize()
        w, h = size.width(), size.height()
        max_w, max_h = self._LOGO_BOX
        if w > 0 and h > 0:
            scale = min(max_w / w, max_h / h)
            disp_w, disp_h = int(round(w * scale)), int(round(h * scale))
        else:
            disp_w, disp_h = max_w, max_h // 2

        widget = QSvgWidget(str(path))
        widget.setFixedSize(disp_w, disp_h)
        return widget