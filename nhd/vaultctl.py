

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from .vault import CredentialStore


def _db_path(args) -> Path:
    return Path(args.db or os.environ.get("NHD_VAULT_DB")
                or Path.home() / ".nhd" / "vault.db")


def _master(prompt: str = "Master password: ") -> str:
    pw = os.environ.get("NHD_VAULT_PASSWORD")
    return pw if pw is not None else getpass.getpass(prompt)


def _unlocked_store(args) -> CredentialStore:
    store = CredentialStore(_db_path(args))
    if not store.is_initialized():
        sys.exit("Vault not initialized. Run: python -m nhd.vaultctl init")
    if not store.unlock(_master()):
        sys.exit("Unlock failed: wrong master password.")
    return store


def _split(csv: str | None) -> list[str]:
    return [x.strip() for x in (csv or "").split(",") if x.strip()]


def cmd_init(args) -> int:
    store = CredentialStore(_db_path(args))
    if store.is_initialized():
        sys.exit(f"Vault already initialized at {store.db_path}")
    pw = _master("New master password: ")
    if os.environ.get("NHD_VAULT_PASSWORD") is None:
        if pw != getpass.getpass("Confirm master password: "):
            sys.exit("Passwords did not match.")
    store.init_vault(pw)
    print(f"Initialized vault at {store.db_path}")
    return 0


def cmd_add(args) -> int:
    store = _unlocked_store(args)
    if store.get_credential(args.name):
        sys.exit(f"Credential {args.name!r} already exists "
                 f"(use 'remove' first, or a different name).")

    ssh_key = None
    passphrase = None
    if args.key_file:
        key_path = Path(args.key_file).expanduser()
        if not key_path.is_file():
            sys.exit(f"Key file not found: {key_path}")
        ssh_key = key_path.read_text()
        if "ENCRYPTED" in ssh_key.splitlines()[0] if ssh_key.splitlines() else False:
            print("warning: key looks passphrase-encrypted; the HUD server "
                  "cannot supply a passphrase to paramiko.", file=sys.stderr)
        if args.passphrase:
            passphrase = getpass.getpass("Key passphrase: ")

    password = None
    if args.password:
        password = getpass.getpass(f"Password for {args.user}: ")

    if not ssh_key and not password:
        sys.exit("Provide --key-file and/or --password (a credential needs a secret).")

    store.add_credential(
        args.name, args.user,
        password=password, ssh_key=ssh_key, ssh_key_passphrase=passphrase,
        match_hosts=_split(args.hosts), match_tags=_split(args.tags),
        is_default=args.default,
    )
    print(f"Added credential {args.name!r} "
          f"({'key' if ssh_key else 'password'}{' +default' if args.default else ''})")
    return 0


def cmd_list(args) -> int:
    store = CredentialStore(_db_path(args))
    if not store.is_initialized():
        sys.exit("Vault not initialized.")
    creds = store.list_credentials()
    if not creds:
        print("(no credentials)")
        return 0
    width = max([len(c.name) for c in creds] + [len("NAME")])
    print(f"{'NAME':<{width}}  {'USERNAME':<16}  {'AUTH':<14}  HOSTS")
    print(f"{'-' * width}  {'-' * 16}  {'-' * 14}  -----")
    for c in creds:
        flags = []
        if c.password:
            flags.append("pw")
        if c.ssh_key:
            flags.append("key")
        if c.is_default:
            flags.append("default")
        hosts = ",".join(c.match_hosts) if c.match_hosts else "-"
        print(f"{c.name:<{width}}  {c.username:<16}  "
              f"{('/'.join(flags) or 'no-secret'):<14}  {hosts}")
    print("\n(NAME is the first column — that's what remove/show/set-default take.)")
    return 0


def cmd_show(args) -> int:
    store = _unlocked_store(args)
    c = store.get_credential(args.name)
    if not c:
        sys.exit(f"No such credential: {args.name}")
    print(f"name:        {c.name}")
    print(f"username:    {c.username}")
    print(f"password:    {'set' if c.has_password else '-'}")
    print(f"ssh_key:     {'set' if c.has_ssh_key else '-'}"
          f"{' (passphrase set)' if c.ssh_key_passphrase else ''}")
    print(f"match_hosts: {', '.join(c.match_hosts) or '-'}")
    print(f"match_tags:  {', '.join(c.match_tags) or '-'}")
    print(f"is_default:  {c.is_default}")
    return 0


def cmd_remove(args) -> int:
    store = _unlocked_store(args)
    if store.remove_credential(args.name):
        print(f"Removed {args.name!r}")
        return 0
    sys.exit(f"No such credential: {args.name}")


def cmd_set_default(args) -> int:
    store = _unlocked_store(args)
    if store.set_default(args.name):
        print(f"{args.name!r} is now the default credential")
        return 0
    sys.exit(f"No such credential: {args.name}")


def cmd_rekey(args) -> int:
    store = CredentialStore(_db_path(args))
    if not store.is_initialized():
        sys.exit("Vault not initialized.")
    old = getpass.getpass("Current master password: ")
    new = getpass.getpass("New master password: ")
    if new != getpass.getpass("Confirm new master password: "):
        sys.exit("Passwords did not match.")
    if store.change_master_password(old, new):
        print("Master password changed.")
        return 0
    sys.exit("Re-key failed: current password incorrect.")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m nhd.vaultctl",
                                 description="Manage the nhd credential vault.")
    ap.add_argument("--db", help="vault db path (default ~/.nhd/vault.db "
                                  "or $NHD_VAULT_DB)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create a new vault").set_defaults(fn=cmd_init)

    a = sub.add_parser("add", help="add a credential")
    a.add_argument("name")
    a.add_argument("--user", "-u", required=True, help="ssh username")
    a.add_argument("--key-file", "-k", help="read private key CONTENTS from this file")
    a.add_argument("--passphrase", action="store_true",
                   help="prompt for the key passphrase (see note: HUD servers "
                        "can't forward it to paramiko)")
    a.add_argument("--password", "-p", action="store_true",
                   help="prompt for a password instead of / in addition to a key")
    a.add_argument("--hosts", help="comma-separated host globs, e.g. 'border*,*.site1'")
    a.add_argument("--tags", help="comma-separated tags")
    a.add_argument("--default", action="store_true", help="make this the catch-all")
    a.set_defaults(fn=cmd_add)

    sub.add_parser("list", help="list credentials (metadata only)").set_defaults(fn=cmd_list)

    s = sub.add_parser("show", help="show one credential's metadata")
    s.add_argument("name")
    s.set_defaults(fn=cmd_show)

    r = sub.add_parser("remove", help="delete a credential")
    r.add_argument("name")
    r.set_defaults(fn=cmd_remove)

    d = sub.add_parser("set-default", help="set the catch-all credential")
    d.add_argument("name")
    d.set_defaults(fn=cmd_set_default)

    sub.add_parser("rekey", help="change the master password").set_defaults(fn=cmd_rekey)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())