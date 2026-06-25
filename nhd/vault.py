"""
Encrypted credential vault for the nethuds desktop wrapper.

A direct descendant of the nterm-qt vault (scottpeterman/nterm-qt,
nterm/vault/store.py): SQLite for storage, Fernet for encryption, a master
password stretched with PBKDF2-HMAC-SHA256, and a verify-token unlock check.
Trimmed to what the nethuds HUD servers can actually consume and given a
resolver that emits nhd's connect contract directly.

Why this shape, specifically for nhd:

  * The HUD servers' /api/connect accepts `key_text` (the private key's
    *contents*, written to a 0600 temp file server-side) but never a key
    *path* from the client. So the vault stores the key body, not a path --
    which is also how nterm-qt stores it. A vault entry therefore round-trips
    straight into /api/connect with no filesystem step on the client.
  * Secrets live only here (encrypted at rest) and in the loopback POST body
    at connect time. They never land in a session YAML file.
  * `cryptography` is already in the dependency tree (paramiko depends on it),
    so this adds no new dependency.

Credential model is deliberately leaner than nterm's: no jump-host fields,
because the HUD servers open a single direct SSH session and have nowhere to
put a bastion. `legacy_ssh` is intentionally NOT stored on the credential --
it is a property of the *device* (does this box speak only old KEX/host-key
algorithms), so it lives on DeviceSession and is supplied at resolve time.
"""

from __future__ import annotations

import base64
import logging
import secrets
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger("nethuds.desktop.vault")

# Matches nterm-qt. High enough to be meaningful, low enough not to stall the
# unlock dialog on a laptop. Stored implicitly via the salt; if this ever
# changes, bump SCHEMA_VERSION and migrate.
_PBKDF2_ITERATIONS = 480_000


@dataclass
class StoredCredential:
    """One credential as held in the vault. Secrets are plaintext in memory
    only while the vault is unlocked; on disk every secret column is Fernet
    ciphertext."""
    id: int
    name: str
    username: str

    # Secret material (encrypted at rest).
    password: Optional[str] = None
    ssh_key: Optional[str] = None            # private key *contents*, not a path
    ssh_key_passphrase: Optional[str] = None

    # Resolution rules. match_hosts are fnmatch globs against the device host;
    # match_tags intersect device tags. is_default is the catch-all.
    match_hosts: list[str] = field(default_factory=list)
    match_tags: list[str] = field(default_factory=list)
    is_default: bool = False

    created_at: Optional[datetime] = None
    last_used: Optional[datetime] = None

    @property
    def has_password(self) -> bool:
        return bool(self.password)

    @property
    def has_ssh_key(self) -> bool:
        return bool(self.ssh_key)


class VaultLocked(RuntimeError):
    """Raised when an operation needs an unlocked vault and it isn't."""


class CredentialStore:
    """Encrypted credential storage (SQLite + Fernet).

    Lifecycle: is_initialized() -> init_vault(master) once -> unlock(master)
    per process -> CRUD -> lock(). list_credentials() works locked (metadata
    only); anything touching secrets requires unlock.
    """

    SCHEMA_VERSION = 1

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else Path.home() / ".nhd" / "vault.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._fernet: Optional[Fernet] = None
        self._unlocked = False

    # ---- lifecycle ----------------------------------------------------------

    def is_initialized(self) -> bool:
        if not self.db_path.exists():
            return False
        conn = sqlite3.connect(str(self.db_path))
        try:
            cur = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='vault_meta'"
            )
            return cur.fetchone() is not None
        finally:
            conn.close()

    def init_vault(self, password: str) -> None:
        if self.is_initialized():
            raise RuntimeError("Vault already initialized")
        salt = secrets.token_bytes(16)
        fernet = Fernet(self._derive_key(password, salt))
        verify_plain = secrets.token_bytes(32)
        verify_enc = fernet.encrypt(verify_plain)

        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.executescript(
                """
                CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value BLOB);
                CREATE TABLE credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    username TEXT NOT NULL,
                    password_enc BLOB,
                    ssh_key_enc BLOB,
                    ssh_key_passphrase_enc BLOB,
                    match_hosts TEXT,
                    match_tags TEXT,
                    is_default INTEGER DEFAULT 0,
                    created_at TEXT,
                    last_used TEXT
                );
                CREATE INDEX idx_credentials_name ON credentials(name);
                CREATE INDEX idx_credentials_default ON credentials(is_default);
                """
            )
            conn.executemany(
                "INSERT INTO vault_meta (key, value) VALUES (?, ?)",
                [
                    ("salt", salt),
                    ("verify", verify_enc),
                    ("verify_plain", verify_plain),
                    ("version", str(self.SCHEMA_VERSION).encode()),
                ],
            )
            conn.commit()
        finally:
            conn.close()
        logger.info("Vault initialized at %s", self.db_path)

    def unlock(self, password: str) -> bool:
        if not self.is_initialized():
            raise RuntimeError("Vault not initialized")
        conn = sqlite3.connect(str(self.db_path))
        try:
            salt = self._meta(conn, "salt")
            verify_enc = self._meta(conn, "verify")
            verify_plain = self._meta(conn, "verify_plain")
            if salt is None or verify_enc is None or verify_plain is None:
                conn.close()
                return False
            fernet = Fernet(self._derive_key(password, salt))
            try:
                if fernet.decrypt(verify_enc) != verify_plain:
                    conn.close()
                    return False
            except InvalidToken:
                conn.close()
                return False
            self._conn = conn
            self._fernet = fernet
            self._unlocked = True
            logger.info("Vault unlocked")
            return True
        except Exception:
            logger.exception("Unlock failed")
            conn.close()
            return False

    def lock(self) -> None:
        if self._conn:
            self._conn.close()
        self._conn = None
        self._fernet = None
        self._unlocked = False
        logger.info("Vault locked")

    @property
    def is_unlocked(self) -> bool:
        return self._unlocked and self._fernet is not None

    # ---- crypto -------------------------------------------------------------

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                         iterations=_PBKDF2_ITERATIONS)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def _meta(conn: sqlite3.Connection, key: str):
        row = conn.execute("SELECT value FROM vault_meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def _encrypt(self, data: Optional[str]) -> Optional[bytes]:
        if not data:
            return None
        if not self._fernet:
            raise VaultLocked("Vault not unlocked")
        return self._fernet.encrypt(data.encode())

    def _decrypt(self, data: Optional[bytes]) -> Optional[str]:
        if not data:
            return None
        if not self._fernet:
            raise VaultLocked("Vault not unlocked")
        return self._fernet.decrypt(data).decode()

    # ---- CRUD ---------------------------------------------------------------

    def add_credential(self, name: str, username: str, *,
                       password: Optional[str] = None,
                       ssh_key: Optional[str] = None,
                       ssh_key_passphrase: Optional[str] = None,
                       match_hosts: Optional[list[str]] = None,
                       match_tags: Optional[list[str]] = None,
                       is_default: bool = False) -> int:
        if not self.is_unlocked:
            raise VaultLocked("Vault not unlocked")
        if is_default:
            self._conn.execute("UPDATE credentials SET is_default=0")
        cur = self._conn.execute(
            """INSERT INTO credentials
               (name, username, password_enc, ssh_key_enc, ssh_key_passphrase_enc,
                match_hosts, match_tags, is_default, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (name, username,
             self._encrypt(password),
             self._encrypt(ssh_key.strip() if ssh_key else None),
             self._encrypt(ssh_key_passphrase),
             ",".join(match_hosts) if match_hosts else None,
             ",".join(match_tags) if match_tags else None,
             int(is_default), datetime.now().isoformat()),
        )
        self._conn.commit()
        return cur.lastrowid

    def update_credential(self, name: str, **kwargs) -> bool:
        if not self.is_unlocked:
            raise VaultLocked("Vault not unlocked")
        if not self.get_credential(name):
            return False
        # field name -> (column, transform)
        enc = self._encrypt
        mapping = {
            "username":           ("username", lambda v: v),
            "password":           ("password_enc", enc),
            "ssh_key":            ("ssh_key_enc", lambda v: enc(v.strip() if v else None)),
            "ssh_key_passphrase": ("ssh_key_passphrase_enc", enc),
            "match_hosts":        ("match_hosts", lambda v: ",".join(v) if v else None),
            "match_tags":         ("match_tags", lambda v: ",".join(v) if v else None),
        }
        updates: dict[str, object] = {}
        for k, v in kwargs.items():
            if k in mapping:
                col, fn = mapping[k]
                updates[col] = fn(v)
            elif k == "is_default":
                if v:
                    self._conn.execute("UPDATE credentials SET is_default=0")
                updates["is_default"] = int(bool(v))
        if not updates:
            return True
        set_clause = ", ".join(f"{c}=?" for c in updates)
        cur = self._conn.execute(
            f"UPDATE credentials SET {set_clause} WHERE name=?",
            [*updates.values(), name],
        )
        self._conn.commit()
        return cur.rowcount > 0

    def rename_credential(self, old: str, new: str) -> bool:
        if not self.is_unlocked:
            raise VaultLocked("Vault not unlocked")
        cur = self._conn.execute(
            "UPDATE credentials SET name=? WHERE name=?", (new, old))
        self._conn.commit()
        return cur.rowcount > 0

    def remove_credential(self, name: str) -> bool:
        conn = self._conn or sqlite3.connect(str(self.db_path))
        try:
            cur = conn.execute("DELETE FROM credentials WHERE name=?", (name,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            if not self._conn:
                conn.close()

    def set_default(self, name: str) -> bool:
        conn = self._conn or sqlite3.connect(str(self.db_path))
        try:
            conn.execute("UPDATE credentials SET is_default=0")
            cur = conn.execute(
                "UPDATE credentials SET is_default=1 WHERE name=?", (name,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            if not self._conn:
                conn.close()

    def get_credential(self, name: str) -> Optional[StoredCredential]:
        if not self.is_unlocked:
            raise VaultLocked("Vault not unlocked")
        row = self._conn.execute(
            "SELECT * FROM credentials WHERE name=?", (name,)).fetchone()
        return self._row_to_credential(row) if row else None

    def list_credentials(self) -> list[StoredCredential]:
        """Metadata-only listing. Works while locked: secret columns are
        reported as presence flags ("***"), never decrypted."""
        conn = self._conn or sqlite3.connect(str(self.db_path))
        try:
            cur = conn.execute(
                """SELECT id, name, username,
                          password_enc IS NOT NULL, ssh_key_enc IS NOT NULL,
                          match_hosts, match_tags, is_default, created_at, last_used
                   FROM credentials ORDER BY is_default DESC, name"""
            )
            out: list[StoredCredential] = []
            for r in cur:
                c = StoredCredential(
                    id=r[0], name=r[1], username=r[2],
                    match_hosts=r[5].split(",") if r[5] else [],
                    match_tags=r[6].split(",") if r[6] else [],
                    is_default=bool(r[7]),
                    created_at=datetime.fromisoformat(r[8]) if r[8] else None,
                    last_used=datetime.fromisoformat(r[9]) if r[9] else None,
                )
                c.password = "***" if r[3] else None
                c.ssh_key = "***" if r[4] else None
                out.append(c)
            return out
        finally:
            if not self._conn:
                conn.close()

    def update_last_used(self, name: str) -> None:
        conn = self._conn or sqlite3.connect(str(self.db_path))
        try:
            conn.execute("UPDATE credentials SET last_used=? WHERE name=?",
                         (datetime.now().isoformat(), name))
            conn.commit()
        finally:
            if not self._conn:
                conn.close()

    def change_master_password(self, old: str, new: str) -> bool:
        """Re-key the vault: re-encrypt every secret under a new master."""
        if not self.unlock(old):
            return False
        creds = [self._row_to_credential(r)
                 for r in self._conn.execute("SELECT * FROM credentials")]
        salt = secrets.token_bytes(16)
        new_fernet = Fernet(self._derive_key(new, salt))
        verify_plain = secrets.token_bytes(32)
        self._conn.execute("UPDATE vault_meta SET value=? WHERE key='salt'", (salt,))
        self._conn.execute("UPDATE vault_meta SET value=? WHERE key='verify'",
                           (new_fernet.encrypt(verify_plain),))
        self._conn.execute("UPDATE vault_meta SET value=? WHERE key='verify_plain'",
                           (verify_plain,))
        for c in creds:
            self._conn.execute(
                """UPDATE credentials SET password_enc=?, ssh_key_enc=?,
                   ssh_key_passphrase_enc=? WHERE name=?""",
                (new_fernet.encrypt(c.password.encode()) if c.password else None,
                 new_fernet.encrypt(c.ssh_key.encode()) if c.ssh_key else None,
                 new_fernet.encrypt(c.ssh_key_passphrase.encode())
                 if c.ssh_key_passphrase else None,
                 c.name),
            )
        self._conn.commit()
        self._fernet = new_fernet
        logger.info("Master password changed")
        return True

    def _row_to_credential(self, row) -> StoredCredential:
        return StoredCredential(
            id=row[0], name=row[1], username=row[2],
            password=self._decrypt(row[3]),
            ssh_key=self._decrypt(row[4]),
            ssh_key_passphrase=self._decrypt(row[5]),
            match_hosts=row[6].split(",") if row[6] else [],
            match_tags=row[7].split(",") if row[7] else [],
            is_default=bool(row[8]),
            created_at=datetime.fromisoformat(row[9]) if row[9] else None,
            last_used=datetime.fromisoformat(row[10]) if row[10] else None,
        )


# ---- resolution -------------------------------------------------------------

@dataclass
class ResolvedIdentity:
    """The connect-time identity for one device, ready to hand to a HUD server.

    These fields are exactly the subset of the /api/connect body that carries
    identity: username + (password XOR key_text), use_keys, and the device-level
    legacy_ssh flag. `source` is the originating credential name (or None for an
    inline/fallback identity) for logging and last-used bookkeeping.
    """
    username: str
    password: Optional[str] = None
    key_text: Optional[str] = None
    key_passphrase: Optional[str] = None
    use_keys: bool = False
    legacy_ssh: bool = False
    source: Optional[str] = None

    @property
    def carries_secret(self) -> bool:
        """True if this identity carries a secret that must NOT go in a URL
        (a private key, or a key passphrase). Password-only identities can ride
        the existing query-string autoconnect path; key identities cannot."""
        return bool(self.key_text or self.key_passphrase)


class CredentialResolver:
    """Maps a device to a vault credential and produces a ResolvedIdentity.

    Scoring mirrors nterm-qt: most-specific host glob wins, tag intersections
    add weight, is_default is the score-1 catch-all. A device may also pin a
    credential by name, which skips scoring entirely.
    """

    def __init__(self, store: CredentialStore):
        self.store = store

    def resolve(self, host: str, *, credential_name: Optional[str] = None,
                tags: Optional[list[str]] = None,
                legacy_ssh: bool = False) -> Optional[ResolvedIdentity]:
        if not self.store.is_unlocked:
            raise VaultLocked("Vault not unlocked")

        cred: Optional[StoredCredential] = None
        if credential_name:
            cred = self.store.get_credential(credential_name)
            if cred is None:
                logger.warning("Pinned credential %r not found for %s",
                               credential_name, host)
        if cred is None:
            cred = self._best_match(host, tags or [])
        if cred is None:
            return None

        self.store.update_last_used(cred.name)
        return self._to_identity(cred, legacy_ssh)

    def _best_match(self, host: str, tags: list[str]) -> Optional[StoredCredential]:
        best: tuple[int, Optional[StoredCredential]] = (0, None)
        for c in self._all():
            score = self._score(c, host, tags)
            if score > best[0]:
                best = (score, c)
        return best[1]

    def _all(self) -> list[StoredCredential]:
        return [self.store._row_to_credential(r)
                for r in self.store._conn.execute("SELECT * FROM credentials")]

    @staticmethod
    def _score(cred: StoredCredential, host: str, tags: list[str]) -> int:
        score = 0
        for pattern in cred.match_hosts:
            if fnmatch(host, pattern):
                specificity = len(pattern) - pattern.count("*") - pattern.count("?")
                score = max(score, 10 + specificity)
        if tags and cred.match_tags:
            score += len(set(tags) & set(cred.match_tags)) * 5
        if cred.is_default and score == 0:
            score = 1
        return score

    @staticmethod
    def _to_identity(cred: StoredCredential, legacy_ssh: bool) -> ResolvedIdentity:
        # Key auth takes priority over password when both are present, matching
        # nterm-qt's resolver and the HUD server (key_text wins over password).
        if cred.ssh_key:
            return ResolvedIdentity(
                username=cred.username, key_text=cred.ssh_key,
                key_passphrase=cred.ssh_key_passphrase, use_keys=True,
                legacy_ssh=legacy_ssh, source=cred.name,
            )
        return ResolvedIdentity(
            username=cred.username, password=cred.password, use_keys=False,
            legacy_ssh=legacy_ssh, source=cred.name,
        )