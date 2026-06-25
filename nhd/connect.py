"""
Connect mechanism for vault-backed, key-capable HUD sessions.

The original POC drove connection through the page's query-string autoconnect:
the wrapper put host/username/password in the URL and the login modal POSTed
/api/connect itself. That path cannot carry a private key -- the modal's
`key_text` only comes from a file <input> -- and putting a key in a URL would
undo the point of an encrypted vault.

So for key auth the wrapper establishes the session itself: it POSTs the
resolved identity (key_text/password, legacy_ssh, ...) to the vendor server's
/api/connect over loopback, then loads the page pointed at the resulting
session so the page *attaches* instead of reconnecting. Secrets live only in
this loopback POST body; they never touch the URL, page JS, or sessionStorage.

  * Session vendors (arista/juniper/cisco) return a `session_id`; the page is
    loaded as `/?session=<id>&name=...` and its resume path attaches.
  * Linux is single-target: /api/connect establishes the one device and returns
    no id; the page is loaded bare (`/?name=...`) and its existing no-params
    branch attaches telemetry to the live collector.

`establish_session` is plain urllib (stdlib, no new dep) so it is unit-testable
without Qt. `ConnectWorker` is the QThread wrapper the UI uses.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Optional

from .vault import ResolvedIdentity

logger = logging.getLogger("nethuds.desktop.connect")


class ConnectError(RuntimeError):
    """The server refused the connection; message is the server's own text."""


@dataclass
class ConnectResult:
    """Outcome of establishing a session: the id to attach with (None for
    single-target Linux) and the host actually connected, for display."""
    session_id: Optional[str]
    host: str


def build_connect_body(identity: ResolvedIdentity, host: str, port: int,
                       timeout: int = 45) -> dict:
    """Assemble the /api/connect JSON body from a resolved identity.

    Only one secret is ever sent: key_text XOR password, mirroring the server's
    own precedence (key_text wins, sets use_keys=True; password sets it False).
    A key path is never sent -- the server only accepts key *contents*.
    """
    body: dict = {
        "host": host,
        "username": identity.username,
        "legacy_ssh": identity.legacy_ssh,
        "port": port,
        "timeout": timeout,
    }
    if identity.key_text:
        body["key_text"] = identity.key_text
        body["use_keys"] = True
        # The server writes key_text to a 0600 temp file and ignores any
        # passphrase field, so an encrypted key must be decrypted upstream or
        # stored unencrypted in the vault. Surface that rather than silently
        # half-working.
        if identity.key_passphrase:
            logger.warning("Resolved key for %s has a passphrase; the HUD "
                           "server cannot supply it to paramiko. Connection "
                           "will fail unless the key is passphrase-less.", host)
    elif identity.password:
        body["password"] = identity.password
        body["use_keys"] = False
    return body


def establish_session(base_url: str, identity: ResolvedIdentity, host: str,
                      port: int = 22, timeout: int = 45) -> ConnectResult:
    """POST /api/connect on a running vendor server and return how to attach.

    Raises ConnectError with the server's message on a non-ok response, and on
    transport errors (the server process died, never bound, etc.).
    """
    body = build_connect_body(identity, host, port, timeout)
    masked = {**body, **({"key_text": "<key>"} if "key_text" in body else {}),
              **({"password": "***"} if "password" in body else {})}
    logger.info("POST %s/api/connect %s", base_url, masked)

    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{base_url}/api/connect", data=data,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        # timeout+15 so the HTTP read outlives the server's own SSH timeout and
        # we get the server's structured error rather than a transport timeout.
        with urllib.request.urlopen(req, timeout=timeout + 15) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode())
            raise ConnectError(payload.get("message") or f"HTTP {e.code}") from e
        except (ValueError, json.JSONDecodeError):
            raise ConnectError(f"HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise ConnectError(f"HUD server unreachable: {e.reason}") from e

    if payload.get("status") != "ok":
        raise ConnectError(payload.get("message") or "connection rejected")

    return ConnectResult(
        session_id=payload.get("session_id"),   # None for single-target Linux
        host=payload.get("host", host),
    )


# --- Qt worker ---------------------------------------------------------------
# Imported lazily-friendly: this module stays importable (and testable) without
# PyQt6, since establish_session above is the part under test.

try:
    from PyQt6.QtCore import QObject, QThread, pyqtSignal
except Exception:  # pragma: no cover - allows headless import of the logic above
    QObject = object  # type: ignore
    QThread = object   # type: ignore
    pyqtSignal = None  # type: ignore


if pyqtSignal is not None:

    class ConnectWorker(QThread):
        """Runs establish_session off the UI thread.

        Emits exactly one of `connected(ConnectResult)` or `failed(str)`. The
        identity is resolved on the UI thread (the vault unlock prompt must be
        modal there) and handed in fully formed, so this thread only does the
        blocking HTTP/SSH round-trip.
        """

        connected = pyqtSignal(object)   # ConnectResult
        failed = pyqtSignal(str)

        def __init__(self, base_url: str, identity: ResolvedIdentity, host: str,
                     port: int = 22, timeout: int = 45, parent=None):
            super().__init__(parent)
            self._base_url = base_url
            self._identity = identity
            self._host = host
            self._port = port
            self._timeout = timeout

        def run(self):
            try:
                result = establish_session(
                    self._base_url, self._identity, self._host,
                    self._port, self._timeout,
                )
            except ConnectError as e:
                self.failed.emit(str(e))
            except Exception as e:  # pragma: no cover - defensive
                logger.exception("Unexpected connect failure")
                self.failed.emit(f"Unexpected error: {e}")
            else:
                self.connected.emit(result)