from __future__ import annotations

import copy
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .ascon import AsconAuthenticationError, ascon_aead128_decrypt, ascon_aead128_encrypt, ascon_hash256

GENESIS_HASH_HEX = "00" * 32
DEMO_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


@dataclass
class VerificationReport:
    ok: bool
    total_records: int
    chain_ok: bool
    aead_ok: bool
    sequence_ok: bool
    anchor_ok: bool
    detected_by_hash_chain: bool
    detected_by_aead: bool
    detected_by_sequence: bool
    first_error: str | None
    elapsed_ms: float


def canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def split_record(record: dict) -> tuple[dict, dict]:
    metadata = {
        "sequence_number": int(record["sequence_number"]),
        "timestamp": str(record["timestamp"]),
        "device_id": str(record["device_id"]),
    }
    plaintext = {
        "temperature": float(record["temperature"]),
        "humidity": float(record["humidity"]),
        "pressure": float(record["pressure"]),
        "light": float(record["light"]),
    }
    return metadata, plaintext


def associated_data(metadata: dict, previous_hash_hex: str) -> bytes:
    ad = dict(metadata)
    ad["previous_hash"] = previous_hash_hex
    return canonical_json_bytes(ad)


def derive_nonce(metadata: dict, previous_hash_hex: str) -> bytes:
    """Derive a deterministic unique nonce for reproducible experiments.

    In a real deployment, use a robust nonce/counter management policy.
    """
    return ascon_hash256(b"nonce|" + associated_data(metadata, previous_hash_hex))[:16]


def compute_record_hash(secure_record_without_record_hash: dict) -> str:
    return ascon_hash256(canonical_json_bytes(secure_record_without_record_hash)).hex()


def secure_log_records(records: Iterable[dict], key: bytes = DEMO_KEY) -> tuple[list[dict], dict]:
    secure_records: list[dict] = []
    prev_hash = GENESIS_HASH_HEX
    for record in records:
        metadata, plaintext = split_record(record)
        nonce = derive_nonce(metadata, prev_hash)
        pt_bytes = canonical_json_bytes(plaintext)
        ad = associated_data(metadata, prev_hash)
        c_and_t = ascon_aead128_encrypt(key, nonce, pt_bytes, ad)
        secure_record = {
            **metadata,
            "nonce": nonce.hex(),
            "previous_hash": prev_hash,
            "ciphertext": c_and_t[:-16].hex(),
            "authentication_tag": c_and_t[-16:].hex(),
        }
        secure_record["record_hash"] = compute_record_hash(secure_record)
        secure_records.append(secure_record)
        prev_hash = secure_record["record_hash"]

    anchor = {
        "record_count": len(secure_records),
        "genesis_hash": GENESIS_HASH_HEX,
        "final_record_hash": prev_hash,
        "anchor_note": "Simulasi trusted anchor: simpan nilai ini di server/medium tepercaya.",
    }
    return secure_records, anchor


def decrypt_secure_record(secure_record: dict, key: bytes = DEMO_KEY) -> dict:
    metadata = {
        "sequence_number": int(secure_record["sequence_number"]),
        "timestamp": secure_record["timestamp"],
        "device_id": secure_record["device_id"],
    }
    prev_hash = secure_record["previous_hash"]
    ad = associated_data(metadata, prev_hash)
    c_and_t = bytes.fromhex(secure_record["ciphertext"]) + bytes.fromhex(secure_record["authentication_tag"])
    plaintext = json.loads(ascon_aead128_decrypt(key, bytes.fromhex(secure_record["nonce"]), c_and_t, ad).decode("utf-8"))
    return {**metadata, **plaintext}


def verify_hash_chain_only(secure_records: list[dict], anchor: dict | None = None) -> VerificationReport:
    start = time.perf_counter()
    prev_hash = GENESIS_HASH_HEX
    first_error = None
    chain_ok = True
    sequence_ok = True

    for idx, rec in enumerate(secure_records, start=1):
        if int(rec.get("sequence_number", -1)) != idx:
            sequence_ok = False
            if first_error is None:
                first_error = f"sequence_number tidak sesuai pada posisi {idx}"
        if rec.get("previous_hash") != prev_hash:
            chain_ok = False
            if first_error is None:
                first_error = f"previous_hash tidak cocok pada sequence {rec.get('sequence_number')}"
        rec_no_hash = {k: v for k, v in rec.items() if k != "record_hash"}
        recomputed = compute_record_hash(rec_no_hash)
        if rec.get("record_hash") != recomputed:
            chain_ok = False
            if first_error is None:
                first_error = f"record_hash tidak valid pada sequence {rec.get('sequence_number')}"
        prev_hash = rec.get("record_hash", "")

    anchor_ok = True
    if anchor is not None:
        if anchor.get("record_count") != len(secure_records):
            anchor_ok = False
            if first_error is None:
                first_error = "jumlah record tidak sesuai dengan anchor tepercaya"
        if anchor.get("final_record_hash") != prev_hash:
            anchor_ok = False
            if first_error is None:
                first_error = "final_record_hash tidak sesuai dengan anchor tepercaya"

    elapsed_ms = (time.perf_counter() - start) * 1000
    ok = chain_ok and sequence_ok and anchor_ok
    return VerificationReport(
        ok=ok,
        total_records=len(secure_records),
        chain_ok=chain_ok,
        aead_ok=True,
        sequence_ok=sequence_ok,
        anchor_ok=anchor_ok,
        detected_by_hash_chain=not chain_ok or not anchor_ok,
        detected_by_aead=False,
        detected_by_sequence=not sequence_ok,
        first_error=first_error,
        elapsed_ms=elapsed_ms,
    )


def verify_full_log(secure_records: list[dict], anchor: dict | None = None, key: bytes = DEMO_KEY) -> VerificationReport:
    start = time.perf_counter()
    chain_report = verify_hash_chain_only(secure_records, anchor)
    aead_ok = True
    first_error = chain_report.first_error

    for rec in secure_records:
        try:
            decrypt_secure_record(rec, key=key)
        except (AsconAuthenticationError, ValueError, json.JSONDecodeError) as exc:
            aead_ok = False
            if first_error is None:
                first_error = f"AEAD gagal pada sequence {rec.get('sequence_number')}: {exc}"
            # Continue checking other records so the summary remains complete.

    elapsed_ms = (time.perf_counter() - start) * 1000
    ok = chain_report.chain_ok and chain_report.sequence_ok and chain_report.anchor_ok and aead_ok
    return VerificationReport(
        ok=ok,
        total_records=len(secure_records),
        chain_ok=chain_report.chain_ok,
        aead_ok=aead_ok,
        sequence_ok=chain_report.sequence_ok,
        anchor_ok=chain_report.anchor_ok,
        detected_by_hash_chain=chain_report.detected_by_hash_chain,
        detected_by_aead=not aead_ok,
        detected_by_sequence=chain_report.detected_by_sequence,
        first_error=first_error,
        elapsed_ms=elapsed_ms,
    )


def decrypt_all_records(secure_records: list[dict], key: bytes = DEMO_KEY) -> list[dict]:
    return [decrypt_secure_record(rec, key=key) for rec in secure_records]


def write_jsonl(records: list[dict], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")


def read_jsonl(path: str | Path) -> list[dict]:
    with Path(path).open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_json(obj: dict, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")


def tamper_ciphertext(records: list[dict]) -> list[dict]:
    out = copy.deepcopy(records)
    target = out[len(out) // 3]
    raw = bytearray.fromhex(target["ciphertext"])
    raw[0] ^= 0x01
    target["ciphertext"] = raw.hex()
    return out


def tamper_tag(records: list[dict]) -> list[dict]:
    out = copy.deepcopy(records)
    target = out[len(out) // 3]
    raw = bytearray.fromhex(target["authentication_tag"])
    raw[-1] ^= 0x01
    target["authentication_tag"] = raw.hex()
    return out


def tamper_timestamp(records: list[dict]) -> list[dict]:
    out = copy.deepcopy(records)
    out[len(out) // 3]["timestamp"] = "2026-06-01 99:99:99"
    return out


def tamper_device_id(records: list[dict]) -> list[dict]:
    out = copy.deepcopy(records)
    out[len(out) // 3]["device_id"] = "sensor_palsu"
    return out


def tamper_delete_record(records: list[dict]) -> list[dict]:
    out = copy.deepcopy(records)
    if len(out) > 5:
        del out[len(out) // 2]
    return out


def tamper_delete_last_record(records: list[dict]) -> list[dict]:
    out = copy.deepcopy(records)
    if out:
        out.pop()
    return out


def tamper_insert_duplicate_record(records: list[dict]) -> list[dict]:
    out = copy.deepcopy(records)
    if len(out) > 5:
        out.insert(len(out) // 2, copy.deepcopy(out[2]))
    return out


def tamper_swap_order(records: list[dict]) -> list[dict]:
    out = copy.deepcopy(records)
    if len(out) > 5:
        i = len(out) // 2
        out[i], out[i + 1] = out[i + 1], out[i]
    return out

