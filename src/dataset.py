from __future__ import annotations

import csv
import math
import random
from datetime import datetime, timedelta
from pathlib import Path


def generate_sensor_records(count: int, device_id: str = "sensor_01", seed: int = 2026) -> list[dict]:
    """Generate deterministic synthetic sensor records for reproducible experiments."""
    rng = random.Random(seed + count)
    start = datetime(2026, 6, 1, 10, 0, 0)
    records: list[dict] = []
    for i in range(1, count + 1):
        t = start + timedelta(minutes=i - 1)
        # Smooth patterns + small noise to look like plausible sensor readings.
        temperature = 30.0 + 1.2 * math.sin(i / 80.0) + rng.uniform(-0.15, 0.15)
        humidity = 76.0 + 4.0 * math.sin(i / 110.0 + 1.0) + rng.uniform(-0.4, 0.4)
        pressure = 1008.0 + 1.5 * math.cos(i / 95.0) + rng.uniform(-0.2, 0.2)
        light = 450.0 + 120.0 * math.sin(i / 60.0 + 0.5) + rng.uniform(-5.0, 5.0)
        records.append(
            {
                "sequence_number": i,
                "timestamp": t.strftime("%Y-%m-%d %H:%M:%S"),
                "device_id": device_id,
                "temperature": round(temperature, 2),
                "humidity": round(humidity, 2),
                "pressure": round(pressure, 2),
                "light": round(light, 2),
            }
        )
    return records


def write_sensor_csv(records: list[dict], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["sequence_number", "timestamp", "device_id", "temperature", "humidity", "pressure", "light"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)


def read_sensor_csv(path: str | Path) -> list[dict]:
    records: list[dict] = []
    with Path(path).open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["sequence_number"] = int(row["sequence_number"])
            for key in ("temperature", "humidity", "pressure", "light"):
                row[key] = float(row[key])
            records.append(row)
    return records
