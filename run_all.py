from __future__ import annotations

import argparse

from src.experiments import run_all


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run secure sensor logging experiments.")
    parser.add_argument(
        "--counts",
        nargs="+",
        type=int,
        default=[100, 500, 1000],
        help="Jumlah record untuk eksperimen performa. Contoh: --counts 100 1000 10000",
    )
    parser.add_argument(
        "--tamper-count",
        type=int,
        default=100,
        help="Jumlah record untuk pengujian skenario manipulasi.",
    )
    args = parser.parse_args()
    run_all(base_dir=".", record_counts=args.counts, tamper_count=args.tamper_count)
