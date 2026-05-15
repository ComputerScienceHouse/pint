#!/usr/bin/env python3
"""Manage FreeIPA certificate profiles via the JSON-RPC API."""

import getpass
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

IPA_HOST = "ipa10-nrh.csh.rit.edu"
BASE_URL = f"https://{IPA_HOST}/ipa"


def login(opener: urllib.request.OpenerDirector, username: str, password: str) -> None:
    body = urllib.parse.urlencode({"user": username, "password": password}).encode()
    req = urllib.request.Request(
        f"{BASE_URL}/session/login_password",
        data=body,
        headers={"Referer": BASE_URL, "Content-Type": "application/x-www-form-urlencoded"},
    )
    resp = opener.open(req)
    if resp.status != 200:
        print(f"Login failed: {resp.status}", file=sys.stderr)
        sys.exit(1)


def rpc(opener: urllib.request.OpenerDirector, method: str, args: list, kwargs: dict) -> dict:
    payload = json.dumps({"method": method, "params": [args, kwargs], "id": 0}).encode()
    req = urllib.request.Request(
        f"{BASE_URL}/json",
        data=payload,
        headers={"Referer": BASE_URL, "Content-Type": "application/json"},
    )
    return json.loads(opener.open(req).read())


def update_profile(opener: urllib.request.OpenerDirector, profile_id: str, cfg_path: Path) -> None:
    result = rpc(opener, "certprofile_mod", [profile_id], {"file": cfg_path.read_text(), "raw": True})
    if result.get("error"):
        print(f"Error updating {profile_id}: {result['error']}", file=sys.stderr)
        sys.exit(1)
    print(f"Updated {profile_id}: ok")


def show_profile(opener: urllib.request.OpenerDirector, profile_id: str) -> None:
    for kwargs in ({"all": True}, {"raw": True, "all": True}):
        result = rpc(opener, "certprofile_show", [profile_id], kwargs)
        if result.get("error"):
            print(f"Error fetching {profile_id}: {result['error']}", file=sys.stderr)
            sys.exit(1)
        data = result["result"]["result"]
        cfg_lines = data.get("ipacertprofileconfig", [])
        if cfg_lines:
            cfg = "\n".join(cfg_lines) if isinstance(cfg_lines, list) else cfg_lines
            print(f"=== {profile_id} ===")
            print(cfg)
            return
    print(f"=== {profile_id} (full response, no config found) ===")
    print(json.dumps(data, indent=2))


def pick_profiles(profiles: list[Path]) -> list[Path]:
    print("Available profiles:")
    for i, p in enumerate(profiles):
        print(f"  {i + 1}. {p.stem}")
    print(f"  {len(profiles) + 1}. all")
    choice = input("Which profile? ").strip()
    if choice == str(len(profiles) + 1) or choice.lower() == "all":
        return profiles
    try:
        return [profiles[int(choice) - 1]]
    except (ValueError, IndexError):
        print("Invalid choice.", file=sys.stderr)
        sys.exit(1)


def reimport_profile(opener: urllib.request.OpenerDirector, profile_id: str, cfg_path: Path) -> None:
    del_result = rpc(opener, "certprofile_del", [profile_id], {})
    if del_result.get("error"):
        if del_result["error"].get("code") == 4001:
            print(f"{profile_id} not found in Dogtag, skipping delete.")
        else:
            print(f"Error deleting {profile_id}: {del_result['error']}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"Deleted {profile_id}.")

    cfg_text = cfg_path.read_text()
    description = next(
        (line.split("=", 1)[1].strip() for line in cfg_text.splitlines() if line.startswith("desc=")),
        profile_id,
    )
    imp_result = rpc(opener, "certprofile_import", [profile_id], {
        "file": cfg_text,
        "description": description,
        "ipacertprofilestoreissued": True,
    })
    if imp_result.get("error"):
        print(f"Error importing {profile_id}: {imp_result['error']}", file=sys.stderr)
        sys.exit(1)
    print(f"Imported {profile_id}: ok")


def main() -> None:
    profiles_dir = Path(__file__).parent / "profiles"
    profiles = sorted(profiles_dir.glob("*.cfg"))
    if not profiles:
        print("No .cfg files found in profiles/", file=sys.stderr)
        sys.exit(1)

    print("Actions:")
    print("  1. update   — push local .cfg to FreeIPA (certprofile_mod)")
    print("  2. show     — fetch current profile from FreeIPA")
    print("  3. reimport — delete and re-import (use when profile config is missing)")
    action = input("Action? ").strip()
    if action not in ("1", "2", "3", "update", "show", "reimport"):
        print("Invalid action.", file=sys.stderr)
        sys.exit(1)

    selected = pick_profiles(profiles)

    username = input("IPA username: ").strip()
    password = getpass.getpass("IPA password: ")

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
    login(opener, username, password)
    print("Authenticated.")

    for cfg in selected:
        if action in ("1", "update"):
            update_profile(opener, cfg.stem, cfg)
        elif action in ("2", "show"):
            show_profile(opener, cfg.stem)
        else:
            reimport_profile(opener, cfg.stem, cfg)


if __name__ == "__main__":
    main()
