#!/usr/bin/env python3
"""Run the platform key rotation sweep against a deployment, from the outside.

Prerequisites (set in the deployment's environment, e.g. `vercel env add`,
then re-deploy so they take effect):

  ENCRYPTION_KEY_NEXT  a fresh Fernet key — see the "Key generation commands"
                       artifact; set ONLY while this sweep is running
  ROTATION_TOKEN       a fresh random token, e.g. `openssl rand -hex 32`,
                       used only to authorize this loop; remove after the run

Usage (nothing here ever prints a decrypted value or a ciphertext):

  uv run scripts/rewrap_sweep.py --host https://api.agentsecrets.tech --token "$ROTATION_TOKEN"

or: REWRAP_HOST=... REWRAP_TOKEN=... python3 scripts/rewrap_sweep.py

The loop continues until both tables report done, printing one line per
batch. Rows the old key cannot read are listed as skipped primary keys; they
are left untouched and the loop still finishes — decide what to do with them
afterwards, never inside an automated loop.
"""

import argparse
import json
import os
import sys
import time
import urllib.request

DEFAULT_BATCH = 500
MAX_ROUNDS = 20000


def next_page(payload):
    """The request body for the next batch, or None when both tables are done."""
    if payload.get("finished"):
        return None
    return {
        "secret_cursor": payload["secrets"]["cursor"],
        "salt_cursor": payload["key_salts"]["cursor"],
        "limit": _limit,
    }


def call_once(payload):
    """One POST to the rewrap endpoint; raises with a readable message on auth."""
    request = urllib.request.Request(
        "%s/api/admin/rotation/rewrap/" % _host.rstrip("/"),
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % _token,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            body = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:200]
        raise SystemExit(
            "HTTP %s from rewrap endpoint: %s" % (exc.code, detail)
        ) from exc
    if body.get("status") != "success":
        raise SystemExit("unexpected response: %s" % json.dumps(body)[:300])
    return body["data"]


def summarize(label, table):
    skipped = ", skipped pk(s) %s" % table["skipped"] if table["skipped"] else ""
    return "%-9s scanned %-7s rewrote %-7s remaining %-6s%s" % (
        label,
        table["scanned"],
        table["rewrapped"],
        table["remaining"],
        skipped,
    )


def main():
    global _host, _token, _limit  # noqa: PLW0603, the script is the only user

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("REWRAP_HOST"))
    parser.add_argument("--token", default=os.environ.get("REWRAP_TOKEN"))
    parser.add_argument("--limit", type=int, default=DEFAULT_BATCH)
    args = parser.parse_args()

    if not args.host or not args.token:
        raise SystemExit("pass --host and --token (or REWRAP_HOST / REWRAP_TOKEN)")
    _host, _token, _limit = args.host, args.token, max(1, min(args.limit, 1000))

    started = time.monotonic()
    payload = {"secret_cursor": 0, "salt_cursor": 0, "limit": _limit}
    rounds = 0
    while payload is not None and rounds < MAX_ROUNDS:
        data = call_once(payload)
        rounds += 1
        print(
            "batch %5d | %s | %s" % (
                rounds,
                summarize("secrets", data["secrets"]),
                summarize("salts", data["key_salts"]),
            ),
            flush=True,
        )
        payload = next_page(data)

    if payload is not None:
        raise SystemExit(
            "stopped after %d rounds with batches still pending — safest to "
            "rerun; the sweep is idempotent" % rounds
        )

    total = call_once({"secret_cursor": 0, "salt_cursor": 0, "limit": _limit})
    secs = time.monotonic() - started
    print(
        "done in %.1fs | secrets remaining on old key: %d | rows skipped: "
        "secrets=%s salts=%s" % (
            secs,
            total["secrets"]["remaining"],
            total["secrets"]["skipped"] or "none",
            total["key_salts"]["skipped"] or "none",
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
