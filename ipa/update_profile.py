#!/usr/bin/env python3
"""Update a FreeIPA certificate profile via the JSON-RPC API."""

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


def update_profile(opener: urllib.request.OpenerDirector, profile_id: str, cfg_path: Path) -> None:
    payload = json.dumps({
        "method": "certprofile_mod",
        "params": [[profile_id], {"file": cfg_path.read_text(), "raw": True}],
        "id": 0,
    }).encode()
    req = urllib.request.Request(
        f"{BASE_URL}/json",
        data=payload,
        headers={"Referer": BASE_URL, "Content-Type": "application/json"},
    )
    resp = opener.open(req)
    result = json.loads(resp.read())
    if result.get("error"):
        print(f"Error updating {profile_id}: {result['error']}", file=sys.stderr)
        sys.exit(1)
    print(f"Updated {profile_id}: {result['result'].get('summary', 'ok')}")


def main() -> None:
    profiles_dir = Path(__file__).parent / "profiles"
    profiles = sorted(profiles_dir.glob("*.cfg"))
    if not profiles:
        print("No .cfg files found in profiles/", file=sys.stderr)
        sys.exit(1)

    print("Available profiles:")
    for i, p in enumerate(profiles):
        print(f"  {i + 1}. {p.stem}")
    print(f"  {len(profiles) + 1}. all")

    choice = input("Update which profile? ").strip()
    if choice == str(len(profiles) + 1) or choice.lower() == "all":
        selected = profiles
    else:
        try:
            selected = [profiles[int(choice) - 1]]
        except (ValueError, IndexError):
            print("Invalid choice.", file=sys.stderr)
            sys.exit(1)

    username = input("IPA username: ").strip()
    password = getpass.getpass("IPA password: ")

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
    login(opener, username, password)
    print("Authenticated.")

    for cfg in selected:
        update_profile(opener, cfg.stem, cfg)


if __name__ == "__main__":
    main()
