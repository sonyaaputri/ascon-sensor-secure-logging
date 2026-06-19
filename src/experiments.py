from __future__ import annotations

import csv
import json
import time
from pathlib import Path

from .dataset import generate_sensor_records, write_sensor_csv
from .secure_logger import (
    DEMO_KEY,
    decrypt_all_records,
    secure_log_records,
    tamper_ciphertext,
    tamper_delete_record,
    tamper_delete_last_record,
    tamper_device_id,
    tamper_insert_duplicate_record,
    tamper_swap_order,
    tamper_tag,
    tamper_timestamp,
    verify_full_log,
    verify_hash_chain_only,
    write_json,
    write_jsonl,
)


def _file_size(path: str | Path) -> int:
    return Path(path).stat().st_size


def _write_csv(rows: list[dict], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def run_performance_experiments(record_counts: list[int], base_dir: str | Path = ".") -> list[dict]:
    base = Path(base_dir)
    data_dir = base / "data"
    output_dir = base / "output"
    rows: list[dict] = []

    for count in record_counts:
        records = generate_sensor_records(count)
        plain_path = data_dir / f"sensor_plain_{count}.csv"
        secure_path = output_dir / f"secure_log_{count}.jsonl"
        anchor_path = output_dir / f"anchor_{count}.json"
        sample_decrypted_path = output_dir / f"sample_decrypted_{count}.json"

        write_sensor_csv(records, plain_path)

        t0 = time.perf_counter()
        secure_records, anchor = secure_log_records(records, key=DEMO_KEY)
        encryption_ms = (time.perf_counter() - t0) * 1000

        write_jsonl(secure_records, secure_path)
        write_json(anchor, anchor_path)

        t0 = time.perf_counter()
        decrypted = decrypt_all_records(secure_records, key=DEMO_KEY)
        decryption_ms = (time.perf_counter() - t0) * 1000
        decryption_matches_plaintext = decrypted == records
        sample_decrypted_path.write_text(json.dumps(decrypted[:5], indent=2, ensure_ascii=False), encoding="utf-8")

        chain_report = verify_hash_chain_only(secure_records, anchor)
        full_report = verify_full_log(secure_records, anchor, key=DEMO_KEY)

        plain_size = _file_size(plain_path)
        secure_size = _file_size(secure_path)
        overhead_percent = ((secure_size - plain_size) / plain_size) * 100 if plain_size else 0.0

        rows.append(
            {
                "jumlah_record": count,
                "waktu_enkripsi_ms": round(encryption_ms, 3),
                "waktu_dekripsi_ms": round(decryption_ms, 3),
                "waktu_verifikasi_hash_chain_ms": round(chain_report.elapsed_ms, 3),
                "waktu_verifikasi_penuh_ms": round(full_report.elapsed_ms, 3),
                "ukuran_plaintext_kb": round(plain_size / 1024, 3),
                "ukuran_secure_log_kb": round(secure_size / 1024, 3),
                "overhead_persen": round(overhead_percent, 2),
                "hasil_dekripsi_sesuai_plaintext": "Ya" if decryption_matches_plaintext else "Tidak",
                "status_verifikasi_normal": "valid" if full_report.ok else "tidak valid",
            }
        )

    _write_csv(rows, output_dir / "summary_performance.csv")
    return rows


def run_tamper_experiments(base_dir: str | Path = ".", count: int = 1000) -> list[dict]:
    base = Path(base_dir)
    output_dir = base / "output"
    records = generate_sensor_records(count)
    secure_records, anchor = secure_log_records(records, key=DEMO_KEY)

    scenarios = [
        ("Normal / tanpa manipulasi", lambda x: x),
        ("Ciphertext diubah 1 byte", tamper_ciphertext),
        ("Authentication tag diubah", tamper_tag),
        ("Timestamp diubah", tamper_timestamp),
        ("Device ID diubah", tamper_device_id),
        ("Satu record dihapus", tamper_delete_record),
        ("Record terakhir dihapus", tamper_delete_last_record),
        ("Record duplikat disisipkan", tamper_insert_duplicate_record),
        ("Urutan dua record ditukar", tamper_swap_order),
    ]

    rows: list[dict] = []
    for name, tamper_fn in scenarios:
        tampered = tamper_fn(secure_records)
        report = verify_full_log(tampered, anchor, key=DEMO_KEY)
        detected = not report.ok
        rows.append(
            {
                "skenario": name,
                "terdeteksi": "Ya" if detected else "Tidak",
                "terdeteksi_oleh_aead": "Ya" if report.detected_by_aead else "Tidak",
                "terdeteksi_oleh_hash_chain_anchor": "Ya" if report.detected_by_hash_chain else "Tidak",
                "terdeteksi_oleh_sequence": "Ya" if report.detected_by_sequence else "Tidak",
                "status_akhir": "Valid" if report.ok else "Gagal diverifikasi",
                "catatan_error_pertama": report.first_error or "-",
                "waktu_verifikasi_ms": round(report.elapsed_ms, 3),
            }
        )

    _write_csv(rows, output_dir / "tamper_results.csv")
    return rows


def make_plots(base_dir: str | Path = ".") -> list[Path]:
    import matplotlib.pyplot as plt

    base = Path(base_dir)
    output_dir = base / "output"
    plot_dir = output_dir / "plots"
    plot_dir.mkdir(parents=True, exist_ok=True)

    with (output_dir / "summary_performance.csv").open("r", encoding="utf-8") as f:
        perf = list(csv.DictReader(f))
    with (output_dir / "tamper_results.csv").open("r", encoding="utf-8") as f:
        tamper = list(csv.DictReader(f))

    counts = [int(r["jumlah_record"]) for r in perf]
    enc = [float(r["waktu_enkripsi_ms"]) for r in perf]
    dec = [float(r["waktu_dekripsi_ms"]) for r in perf]
    ver = [float(r["waktu_verifikasi_hash_chain_ms"]) for r in perf]

    paths: list[Path] = []

    plt.figure(figsize=(7, 4))
    plt.plot(counts, enc, marker="o", label="Enkripsi")
    plt.plot(counts, dec, marker="o", label="Dekripsi")
    plt.plot(counts, ver, marker="o", label="Verifikasi hash chain")
    plt.xlabel("Jumlah record")
    plt.ylabel("Waktu proses (ms)")
    plt.title("Perbandingan Waktu Proses")
    plt.legend()
    plt.tight_layout()
    p = plot_dir / "grafik_waktu_proses.png"
    plt.savefig(p, dpi=200)
    plt.close()
    paths.append(p)

    plain = [float(r["ukuran_plaintext_kb"]) for r in perf]
    secure = [float(r["ukuran_secure_log_kb"]) for r in perf]
    x = range(len(counts))
    width = 0.35
    plt.figure(figsize=(7, 4))
    plt.bar([i - width / 2 for i in x], plain, width=width, label="Data asli")
    plt.bar([i + width / 2 for i in x], secure, width=width, label="Secure log")
    plt.xticks(list(x), [str(c) for c in counts])
    plt.xlabel("Jumlah record")
    plt.ylabel("Ukuran file (KB)")
    plt.title("Perbandingan Ukuran Data Asli dan Secure Log")
    plt.legend()
    plt.tight_layout()
    p = plot_dir / "grafik_overhead_ukuran.png"
    plt.savefig(p, dpi=200)
    plt.close()
    paths.append(p)

    labels = [r["skenario"] for r in tamper]
    values = [1 if r["terdeteksi"] == "Ya" else 0 for r in tamper]
    plt.figure(figsize=(9, 4.5))
    plt.bar(range(len(labels)), values)
    plt.xticks(range(len(labels)), labels, rotation=35, ha="right")
    plt.yticks([0, 1], ["Tidak", "Ya"])
    plt.ylabel("Terdeteksi")
    plt.title("Hasil Deteksi Skenario Manipulasi")
    plt.tight_layout()
    p = plot_dir / "grafik_deteksi_manipulasi.png"
    plt.savefig(p, dpi=200)
    plt.close()
    paths.append(p)

    return paths


def run_all(base_dir: str | Path = ".", record_counts: list[int] | None = None, tamper_count: int = 100) -> None:
    if record_counts is None:
        # Default dibuat cukup cepat untuk pure Python. Untuk eksperimen besar, jalankan --counts 100 1000 10000.
        record_counts = [100, 500, 1000]
    base = Path(base_dir)
    (base / "output").mkdir(parents=True, exist_ok=True)
    (base / "data").mkdir(parents=True, exist_ok=True)

    perf = run_performance_experiments(record_counts, base_dir=base)
    tamper = run_tamper_experiments(base_dir=base, count=tamper_count)
    plots = make_plots(base_dir=base)

    print("Eksperimen selesai. Ringkasan performa:")
    for row in perf:
        print(row)
    print("\nHasil manipulasi:")
    for row in tamper:
        print(row)
    print("\nGrafik tersimpan:")
    for p in plots:
        print(f"- {p}")

