"""Structural and policy validation for the opaque v4 vault record.

The server never decrypts, unwraps, or escrows the vault. It enforces shape,
size, envelope policy, and the client's Ed25519 proof so a compromised or buggy
client cannot silently remove the last recovery factor or swap the vault root.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from apps.common.exceptions import AuthenticationError, BodyValidationError

VAULT_VERSION = 1
AAD_VERSION = 1
RECOVERY_CHALLENGE_TTL = 300
MIN_ARGON_MEMORY = 64 * 1024
MIN_ARGON_TIME = 3
MIN_ARGON_THREADS = 4
MAX_ARGON_MEMORY = 1024 * 1024
MAX_ENVELOPES = 16
MAX_CIPHERTEXT_LEN = 16 * 1024
MAX_CREDENTIAL_ID_LEN = 1024
ENVELOPE_KDFS = {
    "password": "argon2id",
    "recovery": "hkdf-sha256",
    "passkey": "hkdf-sha256",
}


def _fail(message: str) -> None:
    raise BodyValidationError("vault", message)


def _b64(value: Any, field: str, *, length: int | None = None, max_len: int = MAX_CIPHERTEXT_LEN) -> bytes:
    if not isinstance(value, str) or not value:
        _fail(f"{field} is required")
    if len(value) > max_len * 2:
        _fail(f"{field} is too large")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        _fail(f"{field} is not valid base64")
    if length is not None and len(raw) != length:
        _fail(f"{field} has the wrong length")
    if not raw or len(raw) > max_len:
        _fail(f"{field} has an invalid size")
    return raw


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def proof_payload(vault: dict[str, Any], user_id: str) -> str:
    """Reproduce github.com/The-17/agentsecrets/pkg/vault.ProofPayload exactly."""
    lines = [
        "as-vault-proof-v1",
        f"user:{user_id}",
        f"version:{vault['vault_version']}",
        f"private_key:{_sha(vault['private_key']['ciphertext'])}",
    ]
    bridge = vault.get("bridge")
    if bridge:
        lines.append(f"bridge:{_sha(bridge['ciphertext'])}")
    for envelope in sorted(vault["envelopes"], key=lambda item: item["id"]):
        lines.append(
            f"envelope:{envelope['id']}:{envelope['type']}:{_sha(envelope['ciphertext'])}"
        )
    return "\n".join(lines) + "\n"


def verify_proof(vault: dict[str, Any], user_id: str, pinned_pubkey: str | None = None) -> None:
    if pinned_pubkey and vault.get("vault_pubkey") != pinned_pubkey:
        _fail("vault public key changed")
    public_key = _b64(vault.get("vault_pubkey"), "vault_pubkey", length=32)
    proof = vault.get("proof")
    if not isinstance(proof, dict):
        _fail("proof is required")
    signature = _b64(proof.get("signature"), "proof.signature", length=64)
    try:
        VerifyKey(public_key).verify(signature + proof_payload(vault, user_id).encode("utf-8"))
    except BadSignatureError:
        _fail("vault proof signature is invalid")


def recovery_view(vault: dict[str, Any]) -> dict[str, Any]:
    """Return the minimum material a client needs to unlock with a recovery key.

    The challenge endpoint is unauthenticated, so this view omits the password
    envelope. Exposing it would hand an attacker the password-wrapped vault key
    for offline guessing. The recovery envelope is protected by a 256-bit key.
    The proof is omitted because it covers the full envelope set.
    """
    if not isinstance(vault, dict):
        _fail("vault is required")
    envelopes = vault.get("envelopes")
    if not isinstance(envelopes, list):
        _fail("envelopes must be a list")
    recovery = [
        envelope
        for envelope in envelopes
        if isinstance(envelope, dict) and envelope.get("type") == "recovery"
    ]
    if not recovery:
        _fail("vault has no recovery envelope")
    return {
        "version": vault.get("version", VAULT_VERSION),
        "vault_version": vault.get("vault_version", 1),
        "vault_pubkey": vault.get("vault_pubkey"),
        "private_key": vault.get("private_key"),
        "envelopes": recovery,
    }


def build_recovery_challenge(user_id: str) -> tuple[str, str, int]:
    """Return (nonce, challenge_text, expiry_unix).

    The text is what the client signs verbatim. Its layout is fixed so a client
    that predates a formatting change cannot silently sign different bytes.
    """
    nonce = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    expires = int(time.time()) + RECOVERY_CHALLENGE_TTL
    challenge = (
        f"as-vault-recover-v1\n"
        f"user:{user_id}\n"
        f"nonce:{nonce}\n"
        f"expires:{expires}\n"
    )
    return nonce, challenge, expires


def verify_recovery_signature(public_key_b64: str, challenge: str, signature_b64: str) -> None:
    """Verify a detached Ed25519 signature over the exact challenge bytes."""
    public_key = _b64(public_key_b64, "vault_pubkey", length=32)
    signature = _b64(signature_b64, "signature", length=64)
    try:
        VerifyKey(public_key).verify(signature + challenge.encode("utf-8"))
    except BadSignatureError:
        raise AuthenticationError("Recovery failed")


def _envelope_types(vault: dict[str, Any]) -> tuple[bool, int]:
    types = [envelope["type"] for envelope in vault["envelopes"]]
    return "password" in types, sum(t in ("recovery", "passkey") for t in types)


def _validate_envelope(envelope: Any, seen_ids: set[str]) -> None:
    if not isinstance(envelope, dict):
        _fail("each envelope must be an object")
    envelope_id = envelope.get("id")
    if not isinstance(envelope_id, str) or not envelope_id or len(envelope_id) > 64:
        _fail("envelope id is invalid")
    if envelope_id in seen_ids:
        _fail("envelope ids must be unique")
    seen_ids.add(envelope_id)

    envelope_type = envelope.get("type")
    if envelope_type not in ENVELOPE_KDFS:
        _fail(f"unknown envelope type {envelope_type!r}")
    if envelope.get("kdf") != ENVELOPE_KDFS[envelope_type]:
        _fail(f"envelope {envelope_id} has the wrong KDF")
    if envelope.get("aad_version") != AAD_VERSION:
        _fail(f"envelope {envelope_id} has an unsupported AAD version")

    _b64(envelope.get("salt"), f"envelope {envelope_id} salt", length=32)
    _b64(envelope.get("nonce"), f"envelope {envelope_id} nonce", length=12)
    _b64(envelope.get("ciphertext"), f"envelope {envelope_id} ciphertext")

    credential_id = envelope.get("credential_id")
    if envelope_type == "passkey":
        if not isinstance(credential_id, str) or not credential_id:
            _fail(f"envelope {envelope_id} is missing a credential id")
        if len(credential_id) > MAX_CREDENTIAL_ID_LEN:
            _fail(f"envelope {envelope_id} credential id is too long")
    elif credential_id:
        _fail(f"envelope {envelope_id} must not have a credential id")

    if envelope_type == "password":
        params = envelope.get("params")
        if not isinstance(params, dict):
            _fail(f"envelope {envelope_id} is missing KDF parameters")
        memory = params.get("m")
        time_cost = params.get("t")
        threads = params.get("p")
        if not all(isinstance(value, int) and not isinstance(value, bool) for value in (memory, time_cost, threads)):
            _fail(f"envelope {envelope_id} has invalid KDF parameters")
        if memory < MIN_ARGON_MEMORY or time_cost < MIN_ARGON_TIME or threads < MIN_ARGON_THREADS:
            _fail(f"envelope {envelope_id} KDF parameters are below the policy floor")
        if memory > MAX_ARGON_MEMORY:
            _fail(f"envelope {envelope_id} KDF parameters exceed the policy ceiling")
    elif envelope.get("params") is not None:
        _fail(f"envelope {envelope_id} must not carry Argon2 parameters")


def validate_vault(vault: Any, *, user_id: str) -> None:
    if not isinstance(vault, dict):
        _fail("vault must be an object")
    if vault.get("version") != VAULT_VERSION:
        _fail("unsupported vault version")
    vault_version = vault.get("vault_version")
    if not isinstance(vault_version, int) or isinstance(vault_version, bool) or vault_version < 1:
        _fail("vault_version must be a positive integer")
    if not isinstance(vault.get("recovery_confirmed"), bool):
        _fail("recovery_confirmed must be a boolean")

    private_key = vault.get("private_key")
    if not isinstance(private_key, dict):
        _fail("private_key is required")
    if private_key.get("aad_version") != AAD_VERSION:
        _fail("private_key has an unsupported AAD version")
    _b64(private_key.get("nonce"), "private_key nonce", length=12)
    _b64(private_key.get("ciphertext"), "private_key ciphertext")

    bridge = vault.get("bridge")
    if bridge is not None:
        if not isinstance(bridge, dict) or bridge.get("kdf") != "hkdf-sha256":
            _fail("bridge is invalid")
        if bridge.get("aad_version") != AAD_VERSION:
            _fail("bridge has an unsupported AAD version")
        _b64(bridge.get("salt"), "bridge salt", length=32)
        _b64(bridge.get("nonce"), "bridge nonce", length=12)
        _b64(bridge.get("ciphertext"), "bridge ciphertext")

    envelopes = vault.get("envelopes")
    if not isinstance(envelopes, list) or not envelopes:
        _fail("vault must have at least one envelope")
    if len(envelopes) > MAX_ENVELOPES:
        _fail("vault has too many envelopes")
    seen_ids: set[str] = set()
    for envelope in envelopes:
        _validate_envelope(envelope, seen_ids)

    has_password, invisible = _envelope_types(vault)
    if not has_password and not invisible:
        _fail("vault has no usable factor")
    if vault["recovery_confirmed"] and invisible == 0:
        _fail("recovery cannot be confirmed without a recovery factor")
    if vault.get("min_client_version") is not None:
        value = vault["min_client_version"]
        if not isinstance(value, str) or len(value) > 32:
            _fail("min_client_version is invalid")

    proof = vault.get("proof")
    if not isinstance(proof, dict):
        _fail("proof is required")
    if not isinstance(proof.get("timestamp"), int) or isinstance(proof.get("timestamp"), bool):
        _fail("proof.timestamp must be an integer")
    _b64(proof.get("nonce"), "proof.nonce", length=16)
    verify_proof(vault, user_id)


def validate_vault_update(
    current: Any,
    next_vault: Any,
    *,
    expected_version: int,
    user_id: str,
) -> None:
    validate_vault(next_vault, user_id=user_id)
    if next_vault["vault_version"] != expected_version + 1:
        _fail("vault_version must equal expected_version + 1")

    if not current:
        if expected_version != 0:
            _fail("a new vault must start at version 1")
        return

    if current.get("vault_pubkey") != next_vault.get("vault_pubkey"):
        _fail("vault public key is immutable")
    current_password, _ = _envelope_types(current)
    next_password, next_invisible = _envelope_types(next_vault)

    if current.get("recovery_confirmed") and next_invisible == 0:
        _fail("cannot remove the last recovery factor after recovery is confirmed")
    if current_password and not next_password:
        if not next_vault["recovery_confirmed"] or next_invisible == 0:
            _fail("cannot remove the password before recovery is confirmed")
