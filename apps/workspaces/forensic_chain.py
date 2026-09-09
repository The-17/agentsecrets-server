"""Forensic chain integrity helpers.

Server-authoritative content hashing: the server computes and stores its own
entry_hash over the decision-block JSON it persists, then re-verifies against
the same canonical serialization at replay time. This keeps tamper-evidence
self-consistent without depending on byte-for-byte parity with any particular
client emitter's JSON marshaller.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

# Compact separators keep hashing stable regardless of any pretty-printers.
_CANONICAL_SEPARATORS = (",", ":")


def canonical_dumps(obj) -> str:
    """Serialize a JSON value canonically (sorted keys, compact separators)."""
    return json.dumps(obj, sort_keys=True, separators=_CANONICAL_SEPARATORS, default=str)


def compute_entry_hash(event, snapshot, enforcement, resolution) -> str:
    """SHA-256 over the four forensic decision blocks in canonical form."""
    h = hashlib.sha256()
    for block in (event, snapshot, enforcement, resolution):
        h.update(canonical_dumps(block or {}).encode("utf-8"))
    return h.hexdigest()


def compute_chain_hash(prev_chain_hash: str, entry_id: str, created_at: datetime) -> str:
    """SHA-256 linkage hash over (prev_chain_hash, id, microsecond-UTC timestamp).

    Mirrors the emitters' chain construction (sha256(prev + id + ts)) where ts is
    the creation instant formatted to microseconds in UTC. Purely string
    concatenation, so the result is identical whether the emitter is Go or Python.
    """
    prev = prev_chain_hash or "genesis_block"
    ts = created_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return hashlib.sha256((prev + str(entry_id) + ts).encode("utf-8")).hexdigest()
