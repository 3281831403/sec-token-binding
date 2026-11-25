"""Request-bound access-token proofs.

The public surface intentionally consists of eight functions. Tests exercise
these functions directly, so their signatures and return shapes are fixed.
"""
from __future__ import annotations

import hashlib
import hmac
import math
from typing import Any

# Fields of the signed proof string are separated by the ASCII unit
# separator.  It never overlaps with the commas / ampersands that may occur
# inside an individual field, so field content cannot shift parsing.
_FIELD_SEP = "\x1f"
_FIELD_SEP_BYTES = b"\x1f"


def _key_bytes(key: bytes | str) -> bytes:
    """Normalize an HMAC key to bytes."""
    if isinstance(key, str):
        return key.encode("utf-8")
    return bytes(key)


def _body_bytes(body: bytes | str) -> bytes:
    """Normalize a request body to bytes before digesting it."""
    if isinstance(body, str):
        return body.encode("utf-8")
    return bytes(body)


def _canonical_url(url: str) -> str:
    """Normalize case and sort query parameters.

    Scheme/host are case-insensitive, and the binding contract additionally
    treats the path and query names/values case-insensitively, so the whole
    URL is case-folded.  Query parameters are then sorted by their raw
    ``key=value`` segment so equivalent parameter orderings share a fingerprint.
    """
    canonical = url.lower()
    if "?" not in canonical:
        return canonical

    base, query = canonical.split("?", 1)
    parameters = query.split("&")
    canonical_query = "&".join(sorted(parameters))
    return f"{base}?{canonical_query}"


def request_fingerprint(method: str, url: str, body: bytes | str) -> str:
    """Return the digest that identifies a concrete HTTP request."""
    # Defect 01: bind the HTTP method (upper-cased) into the fingerprint.
    # Defect 02: canonicalize URL case and query parameter ordering.
    # Defect 03: digest the full body instead of using its length, so
    # equal-length but different bodies no longer collide.
    body_digest = hashlib.sha256(_body_bytes(body)).hexdigest()
    canonical_url = _canonical_url(url)
    material = f"{method.upper()}\n{canonical_url}\n{body_digest}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def proof_payload(fingerprint: str, nonce: str, issued_at: int, key_id: str) -> bytes:
    """Build the byte string covered by a proof signature."""
    # Defect 04: join unambiguous fields with the unit separator instead of
    # commas, so commas embedded in a field cannot shift field boundaries.
    # Defect 05: include key_id so a proof minted for a rotated/old key id
    # cannot be presented under a different key.
    fields = (
        str(fingerprint),
        str(nonce),
        str(issued_at),
        str(key_id),
    )
    return _FIELD_SEP.join(fields).encode("utf-8")


def make_proof(key: bytes | str, payload: bytes) -> str:
    """Sign a payload and return the encoded proof string."""
    return hmac.new(_key_bytes(key), payload, hashlib.sha256).hexdigest()


def verify_proof(key: bytes | str, payload: bytes, proof: str) -> bool:
    """Check whether proof signs the supplied payload."""
    expected = make_proof(key, payload)
    if not isinstance(proof, str):
        return False
    # Defect 06: constant-time comparison instead of ordinary ``==``.
    # Access the function as ``hmac.compare_digest`` at call time so callers
    # (and tests) patching the hmac module attribute are honored.
    try:
        return hmac.compare_digest(expected, proof)
    except (TypeError, ValueError):
        # Non-ASCII / otherwise incomparable proof values simply do not match.
        return False


def nonce_check(store: dict[str, int], nonce: str, now: int, ttl: int) -> bool:
    """Consume a nonce once, keeping its expiry in the shared store."""
    # Defect 08: purge expired records on every call so an expired nonce does
    # not remain in the store forever and extend its own acceptance window.
    for stale_nonce in [n for n, expires_at in store.items() if expires_at <= now]:
        del store[stale_nonce]

    # Defect 07: a nonce already present (and unexpired) has been consumed, so
    # a replay must be rejected.
    if nonce in store:
        return False

    # Record the absolute expiry timestamp.
    store[nonce] = now + ttl
    return True


def clock_ok(issued_at: int, now: int, window: int) -> bool:
    """Check that an issue time falls inside the accepted time window."""
    # A window must be a real, finite, non-negative duration; an infinite
    # window would effectively disable freshness validation.
    if not isinstance(window, (int, float)) or isinstance(window, bool):
        return False
    if not math.isfinite(window) or window < 0:
        return False

    # Defect 09: reject timestamps that are either too old OR too far in the
    # future, with the boundary values accepted inclusively.
    delta = issued_at - now
    return -window <= delta <= window


def check_binding(token: dict[str, Any], proof: str, request: dict[str, Any]) -> dict[str, Any]:
    """Validate one proof against one request and report each check."""
    fingerprint = request_fingerprint(
        request["method"],
        request["url"],
        request["body"],
    )

    nonce = request["nonce"]
    issued_at = request["issued_at"]
    key_id = request["key_id"]
    now = request["now"]
    window = request["window"]
    nonce_ttl = request["nonce_ttl"]
    nonce_store = request["nonce_store"]

    key_id_ok = token.get("key_id") == key_id

    payload = proof_payload(fingerprint, nonce, issued_at, key_id)
    proof_ok = verify_proof(token.get("key", b""), payload, proof)

    clock_valid = clock_ok(issued_at, now, window)
    nonce_ok = nonce_check(nonce_store, nonce, now, nonce_ttl)

    valid = bool(proof_ok and key_id_ok and clock_valid and nonce_ok)

    return {
        "fingerprint": fingerprint,
        "proof_ok": proof_ok,
        "key_id_ok": key_id_ok,
        "clock_ok": clock_valid,
        "nonce_ok": nonce_ok,
        "valid": valid,
    }


def binding_batch(requests: list[dict[str, Any]], policy: dict[str, Any], now: int) -> dict[str, dict[str, Any]]:
    """Validate a sequence of request envelopes under one policy."""
    results: dict[str, dict[str, Any]] = {}

    window = policy["window"]
    nonce_ttl = policy["nonce_ttl"]
    nonce_store = policy["nonce_store"]

    for envelope in requests:
        # Defect 10: derive every request's own fingerprint and result inside
        # the loop instead of reusing the first request's fingerprint.  The
        # shared policy supplies the clock, TTL and replay store.
        policy_request = {
            **envelope["request"],
            "now": now,
            "window": window,
            "nonce_ttl": nonce_ttl,
            "nonce_store": nonce_store,
        }
        results[envelope["id"]] = check_binding(
            envelope["token"],
            envelope["proof"],
            policy_request,
        )

    return results
