"""Request-bound access-token proofs.

The public surface intentionally consists of eight functions. Tests exercise
these functions directly, so their signatures and return shapes are fixed.
"""
from __future__ import annotations
import hashlib
import hmac
from typing import Any

def request_fingerprint(method: str, url: str, body: bytes | str) -> str:
    """Return the digest that identifies a concrete HTTP request."""
    raise NotImplementedError()

def proof_payload(fingerprint: str, nonce: str, issued_at: int, key_id: str) -> bytes:
    """Build the byte string covered by a proof signature."""
    raise NotImplementedError()

def make_proof(key: bytes | str, payload: bytes) -> str:
    """Sign a payload and return the encoded proof string."""
    raise NotImplementedError()

def verify_proof(key: bytes | str, payload: bytes, proof: str) -> bool:
    """Check whether proof signs the supplied payload."""
    raise NotImplementedError()

def nonce_check(store: dict[str, int], nonce: str, now: int, ttl: int) -> bool:
    """Consume a nonce once, keeping its expiry in the shared store."""
    raise NotImplementedError()

def clock_ok(issued_at: int, now: int, window: int) -> bool:
    """Check that an issue time falls inside the accepted time window."""
    raise NotImplementedError()

def check_binding(token: dict[str, Any], proof: str, request: dict[str, Any]) -> dict[str, Any]:
    """Validate one proof against one request and report each check."""
    raise NotImplementedError()

def binding_batch(requests: list[dict[str, Any]], policy: dict[str, Any], now: int) -> dict[str, dict[str, Any]]:
    """Validate a sequence of request envelopes under one policy."""
    raise NotImplementedError()
