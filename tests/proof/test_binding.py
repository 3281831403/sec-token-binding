from __future__ import annotations

import copy
import hashlib
import hmac

import engine.proof.binding as binding
from engine.proof.binding import (
    binding_batch,
    check_binding,
    clock_ok,
    make_proof,
    nonce_check,
    proof_payload,
    request_fingerprint,
    verify_proof,
)

NOW = 1_700_000_000
KEY = b"correct-horse-battery-staple-0001"


def _fingerprint(method: str, canonical_url: str, body: bytes) -> str:
    body_digest = hashlib.sha256(body).hexdigest()
    material = f"{method.upper()}\n{canonical_url}\n{body_digest}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _request(
    *,
    method: str = "POST",
    url: str = "https://api.example.test/pay?b=2&a=1",
    body: bytes = b"amount=100",
    nonce: str = "nonce-1",
    issued_at: int = NOW,
    key_id: str = "key-a",
    now: int = NOW,
    window: int = 30,
    nonce_ttl: int = 60,
    store: dict[str, int] | None = None,
) -> dict[str, object]:
    return {
        "method": method,
        "url": url,
        "body": body,
        "nonce": nonce,
        "issued_at": issued_at,
        "key_id": key_id,
        "now": now,
        "window": window,
        "nonce_ttl": nonce_ttl,
        "nonce_store": {} if store is None else store,
    }


def _envelope(item_id: str, request: dict[str, object]) -> dict[str, object]:
    token = {"key": KEY, "key_id": request["key_id"]}
    fingerprint = request_fingerprint(
        str(request["method"]),
        str(request["url"]),
        request["body"],
    )
    payload = proof_payload(
        fingerprint,
        str(request["nonce"]),
        int(request["issued_at"]),
        str(request["key_id"]),
    )
    return {
        "id": item_id,
        "token": token,
        "proof": make_proof(KEY, payload),
        "request": request,
    }


def _individual(item: dict[str, object]) -> dict[str, object]:
    request = copy.deepcopy(item["request"])
    request["nonce_store"] = {}
    return check_binding(item["token"], item["proof"], request)


def test_defect_01_fingerprint_ignores_method() -> None:
    url = "https://api.example.test/pay?a=1"
    body = b"amount=100"
    get_fp = request_fingerprint("GET", url, body)
    post_fp = request_fingerprint("POST", url, body)
    assert get_fp != post_fp
    assert post_fp == _fingerprint("POST", url, body)


def test_defect_02_url_canonicalization() -> None:
    first = request_fingerprint(
        "POST",
        "HTTPS://API.Example.Test/Pay?B=2&a=1",
        b"x",
    )
    second = request_fingerprint(
        "POST",
        "https://api.example.test/pay?a=1&b=2",
        b"x",
    )
    assert first == second
    assert first == _fingerprint(
        "POST",
        "https://api.example.test/pay?a=1&b=2",
        b"x",
    )


def test_defect_03_body_length_collision() -> None:
    url = "https://api.example.test/pay?a=1"
    first = request_fingerprint("POST", url, b"AAAA")
    second = request_fingerprint("POST", url, b"BBBB")
    assert len(b"AAAA") == len(b"BBBB")
    assert first != second
    assert first == _fingerprint("POST", url, b"AAAA")


def test_defect_04_proof_payload_byte_composition() -> None:
    first = proof_payload("fp-1", "nonce,7", 1700, "key-a")
    second = proof_payload("fp-1", "nonce", "7,1700", "key-a")
    assert first != second
    assert first == b"fp-1\x1fnonce,7\x1f1700\x1fkey-a"


def test_defect_05_proof_payload_ignores_key_id() -> None:
    old_payload = proof_payload("fp-1", "nonce-1", NOW, "key-old")
    new_payload = proof_payload("fp-1", "nonce-1", NOW, "key-new")
    assert old_payload != new_payload
    old_proof = make_proof(KEY, old_payload)
    assert verify_proof(KEY, new_payload, old_proof) is False


def test_defect_06_verify_uses_constant_time_compare(monkeypatch) -> None:
    payload = b"payload"
    valid = make_proof(KEY, payload)
    call_count = 0
    real_compare = hmac.compare_digest

    def tracked_compare(left, right) -> bool:
        nonlocal call_count
        call_count += 1
        return real_compare(left, right)

    monkeypatch.setattr(binding.hmac, "compare_digest", tracked_compare)
    tampered = ("0" if valid[0] != "0" else "1") + valid[1:]
    assert verify_proof(KEY, payload, valid) is True
    assert verify_proof(KEY, payload, tampered) is False
    assert call_count >= 1


def test_defect_07_replayed_nonce_second_check_succeeds() -> None:
    store: dict[str, int] = {}
    assert nonce_check(store, "nonce-1", NOW, 30) is True
    assert nonce_check(store, "nonce-1", NOW, 30) is False


def test_defect_08_expired_nonce_entries_are_not_removed() -> None:
    store = {"expired-nonce": NOW - 1}
    assert nonce_check(store, "fresh-nonce", NOW, 30) is True
    assert "expired-nonce" not in store
    assert store["fresh-nonce"] == NOW + 30


def test_defect_09_clock_accepts_future_timestamp() -> None:
    assert clock_ok(NOW + 31, NOW, 30) is False
    assert clock_ok(NOW + 30, NOW, 30) is True
    assert clock_ok(NOW - 30, NOW, 30) is True
    assert clock_ok(NOW - 31, NOW, 30) is False
    assert clock_ok(NOW, NOW, float("inf")) is False


def test_defect_10_batch_reuses_first_fingerprint() -> None:
    first = _envelope("request-1", _request(body=b"amount=100", nonce="nonce-1"))
    second = _envelope("request-2", _request(body=b"amount=2000", nonce="nonce-2"))
    policy = {"window": 30, "nonce_ttl": 60, "nonce_store": {}}
    results = binding_batch([first, second], policy, NOW)
    assert results["request-1"]["valid"] is True
    assert results["request-2"]["valid"] is True


def test_extra_same_request_with_new_nonce_changes_proof() -> None:
    fingerprint = request_fingerprint(
        "POST",
        "https://api.example.test/pay?a=1&b=2",
        b"amount=100",
    )
    first_payload = proof_payload(fingerprint, "nonce-a", NOW, "key-a")
    second_payload = proof_payload(fingerprint, "nonce-b", NOW, "key-a")
    first_proof = make_proof(KEY, first_payload)
    second_proof = make_proof(KEY, second_payload)
    assert first_proof != second_proof
    assert second_payload == (
        fingerprint.encode("utf-8")
        + b"\x1f"
        + b"nonce-b"
        + b"\x1f"
        + str(NOW).encode("ascii")
        + b"\x1f"
        + b"key-a"
    )
    assert second_proof == hmac.new(KEY, second_payload, hashlib.sha256).hexdigest()


def test_extra_tampered_method_is_rejected() -> None:
    item = _envelope("request-1", _request(method="POST", nonce="nonce-1"))
    tampered = copy.deepcopy(item["request"])
    tampered["method"] = "GET"
    result = check_binding(item["token"], item["proof"], tampered)
    assert result["valid"] is False


def test_extra_replayed_nonce_is_rejected_by_check_binding() -> None:
    item = _envelope("request-1", _request(nonce="nonce-1"))
    first = check_binding(item["token"], item["proof"], item["request"])
    second = check_binding(item["token"], item["proof"], item["request"])
    assert first["valid"] is True
    assert second["nonce_ok"] is False
    assert second["valid"] is False


def test_extra_future_issued_at_is_rejected_by_check_binding() -> None:
    item = _envelope(
        "request-1",
        _request(issued_at=NOW + 60, nonce="nonce-1"),
    )
    result = check_binding(item["token"], item["proof"], item["request"])
    assert result["clock_ok"] is False
    assert result["valid"] is False


def test_extra_batch_results_match_individual_checks() -> None:
    first = _envelope("request-1", _request(body=b"a", nonce="nonce-1"))
    second = _envelope("request-2", _request(body=b"bb", nonce="nonce-2"))
    policy = {"window": 30, "nonce_ttl": 60, "nonce_store": {}}
    batch_results = binding_batch([first, second], policy, NOW)
    assert batch_results["request-1"] == _individual(first)
    assert batch_results["request-2"] == _individual(second)